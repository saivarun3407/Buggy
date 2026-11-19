"""Agent-coordination tools — the agent graph plus the mailbox.

Mirrors ``buggy.tools.opplan``: a ``build_*_tools()`` factory and a
``*_TOOL_NAMES`` set. Three tools render or mutate the coordination state
owned by ``CoordinatorMiddleware``:

  * ``view_agent_graph`` — read-only render of the ``agent_graph`` registry.
  * ``send_message``     — append a message to another agent's mailbox.
  * ``read_messages``    — return the caller's unread messages and mark them
                           read.

The caller of ``send_message`` / ``read_messages`` is always the agent the
middleware is attached to, so both resolve the caller id from a reference to
the middleware instance rather than from state.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, get_args
from uuid import uuid4

from langchain_core.messages import ToolMessage
from langchain_core.tools import InjectedToolCallId, tool
from langgraph.prebuilt import InjectedState
from langgraph.types import Command

from buggy.middleware._injection_detector import detect_injection
from buggy.middleware.untrusted_output import format_untrusted_envelope

COORDINATOR_TOOL_NAMES: frozenset[str] = frozenset(
    {"view_agent_graph", "send_message", "read_messages"}
)

_EMPTY_GRAPH_LINE = "No agents registered yet."
_NO_MESSAGES_LINE = "No unread messages."

# The message type/priority state machines. Defined here (the leaf module the
# coordinator middleware imports) so there is one source. The Literal drives
# both the runtime validation set and the ``Message`` type the middleware
# builds. ``PRIORITY_ORDER`` fixes the read ordering, urgent first.
MessageType = Literal["query", "instruction", "information"]
MessagePriority = Literal["low", "normal", "high", "urgent"]
MESSAGE_TYPES: frozenset[str] = frozenset(get_args(MessageType))
MESSAGE_PRIORITIES: frozenset[str] = frozenset(get_args(MessagePriority))
PRIORITY_ORDER: tuple[str, ...] = ("urgent", "high", "normal", "low")

_PRIORITY_RANK: dict[str, int] = {name: rank for rank, name in enumerate(PRIORITY_ORDER)}


def render_agent_graph(agent_graph: dict[str, dict]) -> str:
    """Render the registry as an indented tree.

    Roots (no parent, or a parent id absent from the graph) come first; a
    node's children are indented two spaces under it. Siblings and roots are
    ordered by ``spawned_at`` then ``agent_id`` so the output is
    deterministic. Every registered agent appears exactly once, even if its
    parent linkage forms an orphan or a cycle.
    """
    if not agent_graph:
        return _EMPTY_GRAPH_LINE

    children: dict[str | None, list[dict]] = {}
    for node in agent_graph.values():
        parent = node.get("parent_id")
        if parent not in agent_graph:
            parent = None
        children.setdefault(parent, []).append(node)

    def _order(node: dict) -> tuple[str, str]:
        return (node.get("spawned_at") or "", node.get("agent_id") or "")

    lines: list[str] = []
    visited: set[str] = set()

    def _emit(node: dict, depth: int) -> None:
        agent_id = node.get("agent_id", "?")
        if agent_id in visited:
            return
        visited.add(agent_id)
        status = str(node.get("status", "")).upper()
        role = node.get("role", "?")
        lines.append(f"{'  ' * depth}{agent_id} [{status}] {role}")
        for child in sorted(children.get(agent_id, []), key=_order):
            _emit(child, depth + 1)

    for root in sorted(children.get(None, []), key=_order):
        _emit(root, 0)
    for node in sorted(agent_graph.values(), key=_order):
        _emit(node, 0)

    return "\n".join(lines)


def render_messages(messages: list[dict]) -> str:
    """Render a message list as plain text, highest priority first.

    Sort is by priority (urgent before low) then ``sent_at`` ascending, so a
    tie resolves oldest-first. Each message is one block naming the sender,
    type, priority, and body. No XML.
    """
    ordered = sorted(
        messages,
        key=lambda m: (_PRIORITY_RANK.get(str(m.get("priority")), 99), m.get("sent_at") or ""),
    )
    blocks: list[str] = []
    for message in ordered:
        sender = message.get("from_agent_id", "?")
        mtype = message.get("type", "?")
        priority = message.get("priority", "?")
        body = message.get("body", "")
        blocks.append(f"From {sender} [{priority} {mtype}]:\n{body}")
    return "\n\n".join(blocks)


def build_coordinator_tools(
    agent_id_ref: Callable[[], str | None] | None = None,
) -> list:
    """Create the coordination tools.

    The attached agent's invocation-scoped id is read from injected state.
    """

    @tool(
        description=(
            "Show the live tree of agents running in this engagement. "
            "Returns each agent's id, status, and role, with children "
            "indented under their parent. Read-only — it reports the current "
            "roster and changes nothing."
        )
    )
    def view_agent_graph(
        state: Annotated[dict, InjectedState],
        tool_call_id: Annotated[str, InjectedToolCallId] = "",
    ) -> Command[Any]:
        """Render the agent graph from state as a plain-text tree."""
        graph = state.get("agent_graph") or {}
        return Command(
            update={
                "messages": [
                    ToolMessage(content=render_agent_graph(graph), tool_call_id=tool_call_id)
                ],
            }
        )

    @tool(
        description=(
            "Send a message to another agent's mailbox. `to_agent_id` must be "
            "an id shown by `view_agent_graph`. `message_type` is one of "
            "query / instruction / information; `priority` is one of "
            "low / normal / high / urgent. The recipient reads it with "
            "`read_messages`."
        )
    )
    def send_message(
        to_agent_id: str,
        body: str,
        message_type: str = "information",
        priority: str = "normal",
        state: Annotated[dict, InjectedState] = None,  # type: ignore[assignment]
        tool_call_id: Annotated[str, InjectedToolCallId] = "",
    ) -> Command[Any]:
        """Append a well-formed message to ``mailboxes[to_agent_id]``.

        Fails closed on an invalid type/priority or an unknown recipient —
        no mailbox is created for an id absent from ``agent_graph``.
        """
        if message_type not in MESSAGE_TYPES:
            return _error(
                tool_call_id,
                f"Invalid message_type {message_type!r}. "
                f"Use one of: {', '.join(sorted(MESSAGE_TYPES))}.",
            )
        if priority not in MESSAGE_PRIORITIES:
            return _error(
                tool_call_id,
                f"Invalid priority {priority!r}. "
                f"Use one of: {', '.join(sorted(MESSAGE_PRIORITIES))}.",
            )
        graph = (state or {}).get("agent_graph") or {}
        if to_agent_id not in graph:
            return _error(
                tool_call_id,
                f"No agent {to_agent_id!r} in the graph. "
                "Call view_agent_graph() for valid recipient ids.",
            )

        from_agent_id = str(
            (state or {}).get("coordinator_agent_id")
            or (agent_id_ref() if agent_id_ref else None)
            or "unknown"
        )
        message = {
            "message_id": uuid4().hex,
            "from_agent_id": from_agent_id,
            "to_agent_id": to_agent_id,
            "type": message_type,
            "priority": priority,
            "body": body,
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "read": False,
        }
        return Command(
            update={
                "mailboxes": {to_agent_id: [message]},
                "messages": [
                    ToolMessage(
                        content=f"Message delivered to {to_agent_id}.",
                        tool_call_id=tool_call_id,
                    )
                ],
            }
        )

    @tool(
        description=(
            "Read your own unread messages, highest priority first, and mark "
            "them read. Returns a plain-text list of sender, type, priority, "
            "and body, or a line saying there are none."
        )
    )
    def read_messages(
        state: Annotated[dict, InjectedState],
        tool_call_id: Annotated[str, InjectedToolCallId] = "",
    ) -> Command[Any]:
        """Render and mark-read the caller's unread mailbox messages.

        The read-flagging rides the ``mailboxes`` reducer: re-emitting each
        read message with ``read=True`` and the same ``message_id`` updates
        it in place (``_dedupe_messages`` merges per field). Peer-authored
        bodies are attacker-influenceable, so the rendered text is wrapped in
        the same ``<UNTRUSTED_TOOL_OUTPUT>`` envelope the untrusted-output
        middleware would apply. That middleware cannot do it here because it
        only rewrites ``ToolMessage`` results and this tool returns a
        ``Command`` to carry the mark-read state update.
        """
        me = state.get("coordinator_agent_id") or (agent_id_ref() if agent_id_ref else None)
        box = (state.get("mailboxes") or {}).get(me) or []
        unread = [m for m in box if not m.get("read")]
        if not unread:
            return Command(
                update={
                    "messages": [ToolMessage(content=_NO_MESSAGES_LINE, tool_call_id=tool_call_id)],
                }
            )

        rendered = render_messages(unread)
        verdict = detect_injection(rendered)
        enveloped = format_untrusted_envelope(
            origin="read_messages",
            tool_call_id=tool_call_id,
            risk=verdict.risk,
            categories=sorted(c.value for c in verdict.categories),
            body=rendered,
        )
        marked = {me: [{**m, "read": True} for m in unread]}
        return Command(
            update={
                "mailboxes": marked,
                "messages": [ToolMessage(content=enveloped, tool_call_id=tool_call_id)],
            }
        )

    return [view_agent_graph, send_message, read_messages]


def _error(tool_call_id: str, text: str) -> Command[Any]:
    """A failed tool call that reports ``text`` and mutates no state."""
    return Command(
        update={
            "messages": [ToolMessage(content=text, tool_call_id=tool_call_id, status="error")],
        }
    )


__all__ = [
    "COORDINATOR_TOOL_NAMES",
    "MESSAGE_PRIORITIES",
    "MESSAGE_TYPES",
    "MessagePriority",
    "MessageType",
    "PRIORITY_ORDER",
    "build_coordinator_tools",
    "render_agent_graph",
    "render_messages",
]
