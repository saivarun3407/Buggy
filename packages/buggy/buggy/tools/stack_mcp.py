"""Agent-side tools for the stack's own MCP servers.

Four servers hold what agents must not do themselves, or must not be able to
alter:

``recon``    read-only pipeline data            (buggy.pipeline.mcp_server)
``capture``  evidence HTTP + deterministic probes (buggy.capture.mcp_server)
``scope``    enforced scope + program data       (buggy.capture.scope_server)
``browser``  scope-enforced browser              (buggy.scoped_browser.mcp_server)

Each tool here is a thin MCP client call. Two things are deliberately not
left to the model:

* the engagement is taken from the run's config, never from a tool argument,
  so an agent cannot read or act on another engagement;
* nothing is contacted at import time. A server is reached when its tool is
  called, and an unreachable server is an error result, not a crash.

A server is enabled by its URL variable (``BUGGY_MCP_RECON_URL``,
``BUGGY_MCP_CAPTURE_URL``, ``BUGGY_MCP_SCOPE_URL``, ``BUGGY_MCP_BROWSER_URL``);
unset means its tools are not offered.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from typing import Any

from langchain_core.tools import tool

from buggy.tools.research_web import research_fetch, web_enabled
from buggy_core.utils.engagement_scope import get_active_engagement
from buggy_core.utils.logging import get_logger

log = get_logger("tools.stack_mcp")

SERVER_ENV = {
    "recon": "BUGGY_MCP_RECON_URL",
    "capture": "BUGGY_MCP_CAPTURE_URL",
    "scope": "BUGGY_MCP_SCOPE_URL",
    "browser": "BUGGY_MCP_BROWSER_URL",
}
CALL_TIMEOUT_SECONDS = 180.0


def server_url(server: str) -> str:
    return (os.environ.get(SERVER_ENV[server]) or "").strip()


def current_engagement() -> str:
    """The run's engagement slug: run config first, then the active-engagement context."""
    try:
        from langgraph.config import get_config  # noqa: PLC0415

        configurable = (get_config() or {}).get("configurable") or {}
        name = configurable.get("engagement_name")
        if isinstance(name, str) and name:
            return name
    except Exception:  # noqa: BLE001, S110 - outside a run there is no config
        pass
    return get_active_engagement() or os.environ.get("BUGGY_ENGAGEMENT_ID", "")


def current_actor() -> str:
    """Who is acting in this run: agent name plus the thread, never chosen by the model.

    The capture server records it as the author of findings, facts and lessons
    and uses it as the worker identity for claims.
    """
    # Outside an agent run (the bridge for an external agent) the process names the actor.
    name, thread = (os.environ.get("BUGGY_ACTOR") or "").strip() or "agent", ""
    try:
        from langgraph.config import get_config  # noqa: PLC0415

        config = get_config() or {}
        configurable = config.get("configurable") or {}
        metadata = config.get("metadata") or {}
        for candidate in (
            metadata.get("lc_agent_name"),
            configurable.get("agent_name"),
            metadata.get("langgraph_node"),
        ):
            if isinstance(candidate, str) and candidate.strip():
                name = candidate.strip()
                break
        thread = str(configurable.get("thread_id") or "")
    except Exception:  # noqa: BLE001, S110 - outside a run there is no config
        pass
    return f"{name}:{thread[:12]}" if thread else name


def _result_text(result: Any) -> str:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        payload = structured.get("result", structured)
        return json.dumps(payload, indent=2, default=str)
    parts = [getattr(item, "text", "") for item in getattr(result, "content", []) or []]
    return "\n".join(p for p in parts if p) or "{}"


async def call_mcp(server: str, tool_name: str, arguments: dict[str, Any]) -> str:
    """Call one tool on one of the stack's MCP servers; always returns JSON text."""
    url = server_url(server)
    if not url:
        return json.dumps(
            {"error": f"the {server} server is not configured ({SERVER_ENV[server]})"}
        )
    try:
        from mcp import ClientSession  # noqa: PLC0415 - optional dependency
        from mcp.client.streamable_http import streamablehttp_client  # noqa: PLC0415
    except ImportError:
        return json.dumps({"error": "the MCP client is not installed (pip install 'buggy[mcp]')"})

    async def _call() -> str:
        from buggy.pipeline.mcp_http import client_headers  # noqa: PLC0415

        async with streamablehttp_client(url, headers=client_headers()) as (
            read,
            write,
            _session_id,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return _result_text(await session.call_tool(tool_name, arguments))

    try:
        return await asyncio.wait_for(_call(), timeout=CALL_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - the agent gets a result, not a stack trace
        log.warning("stack_mcp: %s.%s failed: %s", server, tool_name, exc)
        return json.dumps(
            {"error": f"{server} server call failed: {type(exc).__name__}: {str(exc)[:300]}"}
        )


def call_mcp_sync(server: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Blocking :func:`call_mcp` for synchronous callers; always returns a dict.

    Runs the call on its own thread and event loop, so it is safe to use from
    code that may or may not already be inside a running loop.
    """
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["text"] = asyncio.run(call_mcp(server, tool_name, arguments))
        except Exception as exc:  # noqa: BLE001 - reported to the caller as data
            box["text"] = json.dumps({"error": f"{type(exc).__name__}: {str(exc)[:300]}"})

    thread = threading.Thread(target=run, name=f"mcp-{server}-{tool_name}", daemon=True)
    thread.start()
    thread.join(CALL_TIMEOUT_SECONDS + 5)
    if thread.is_alive():
        return {"error": f"{server} server call timed out"}
    try:
        parsed = json.loads(box.get("text") or "{}")
    except ValueError:
        return {"error": f"{server} server returned a non-JSON result"}
    return parsed if isinstance(parsed, dict) else {"result": parsed}


def server_configured(server: str) -> bool:
    """Whether this deployment runs the named stack MCP server."""
    return bool(server_url(server))


async def gateway_http(
    method: str, url: str, headers_json: str = "", body: str = "", note: str = ""
) -> dict[str, Any]:
    """One request through the evidence gateway, as a dict.

    Older in-process tools call this instead of opening their own connection,
    so every request to a target passes the same scope check, approval hold,
    rate limit and recording, from a container that is not the agent runtime.
    """
    text = await _engagement_call(
        "capture",
        "http_send",
        method=method,
        url=url,
        headers_json=headers_json,
        body=body,
        note=note,
    )
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"error": "the evidence gateway returned a non-JSON result"}
    return parsed if isinstance(parsed, dict) else {"error": "unexpected gateway result"}


def gateway_failure(result: dict[str, Any]) -> str | None:
    """Why a gateway result is not a response, or ``None`` when it is one."""
    if result.get("error"):
        return str(result["error"])
    if result.get("status") == "refused":
        return f"{result.get('code')}: {result.get('detail')}"
    return None


async def browser_call(tool_name: str, **arguments: Any) -> dict[str, Any]:
    """One scoped-browser call for the current engagement, as a dict."""
    text = await _engagement_call("browser", tool_name, **arguments)
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"error": "the scoped browser returned a non-JSON result"}
    return parsed if isinstance(parsed, dict) else {"result": parsed}


async def _engagement_call(server: str, tool_name: str, **arguments: Any) -> str:
    engagement = current_engagement()
    if not engagement:
        return json.dumps({"error": "no engagement is active for this run"})
    return await call_mcp(server, tool_name, {"engagement": engagement, **arguments})


# ── recon: read-only pipeline data ───────────────────────────────────


@tool
async def recon_summary() -> str:
    """Deterministic recon already done for this engagement: record counts by type, the last
    pipeline run and what it changed. Start here instead of running recon tools."""
    return await _engagement_call("recon", "recon_summary")


@tool
async def recon_assets(limit: int = 200) -> str:
    """In-scope assets (hosts) the pipeline has facts about, with record counts."""
    return await _engagement_call("recon", "recon_assets", limit=limit)


@tool
async def recon_query(
    record_type: str = "", asset: str = "", contains: str = "", limit: int = 50, offset: int = 0
) -> str:
    """Query pipeline records. record_type: subdomain, dns_record, port, http_service,
    technology, tls, header, url, js_file, endpoint, api_spec, api_operation, graphql,
    parameter, js_finding, vulnerability, secret, and from web and API recon: auth_surface
    (sign-in, sign-up, reset, MFA, OAuth and admin pages by kind), api_base (API roots and
    versions), api_profile (how an API endpoint answered a GET with no login), web_finding
    (missing headers, cookie flags, version banners). Filter by asset (host) and/or a
    substring of the value. Paged."""
    return await _engagement_call(
        "recon",
        "recon_query",
        record_type=record_type,
        asset=asset,
        contains=contains,
        limit=limit,
        offset=offset,
    )


@tool
async def recon_record(record_id: str) -> str:
    """One pipeline record with every observation: which tools reported it, when, raw_ref."""
    return await _engagement_call("recon", "recon_record", record_id=record_id)


@tool
async def recon_diff(run_id: str = "") -> str:
    """What the latest (or given) pipeline run added, changed or removed."""
    return await _engagement_call("recon", "recon_diff", run_id=run_id)


@tool
async def recon_raw(raw_ref: str, context_lines: int = 0) -> str:
    """The unparsed scanner output behind a record's raw_ref (argv, version, hash, line)."""
    return await _engagement_call(
        "recon", "recon_raw", raw_ref=raw_ref, context_lines=context_lines
    )


@tool
async def recon_request_rerun(asset: str, reason: str = "") -> str:
    """Ask the pipeline to re-run for ONE in-scope asset (host, host:port or URL). You cannot
    choose scanners or flags. Returns a request id; check it with recon_rerun_status."""
    return await _engagement_call("recon", "recon_request_rerun", asset=asset, reason=reason)


@tool
async def recon_rerun_status(request_id: str) -> str:
    """Status of a re-run request: pending, completed, rejected or failed."""
    return await _engagement_call("recon", "recon_rerun_status", request_id=request_id)


# ── capture: evidence HTTP and probes ────────────────────────────────


@tool
async def http_send(
    method: str,
    url: str,
    headers_json: str = "",
    body: str = "",
    note: str = "",
    identity: str = "",
) -> str:
    """Send one HTTP request to an in-scope target through the capture gateway. The exchange
    is recorded outside your reach; the returned capture_id is what a finding cites as proof.
    Redirects are returned, not followed. A state-changing method may return
    APPROVAL_REQUIRED: tell the operator, then re-send the identical request. identity names a
    test account from identities_list: the gateway logs in and attaches the session, so you
    never handle a password or token."""
    return await _engagement_call(
        "capture",
        "http_send",
        method=method,
        url=url,
        headers_json=headers_json,
        body=body,
        note=note,
        identity=identity,
    )


@tool
async def http_replay(capture_id: str) -> str:
    """Re-send a captured request from the gateway and compare with the original, to show
    that a finding reproduces."""
    return await _engagement_call("capture", "http_replay", capture_id=capture_id)


@tool
async def http_capture(capture_id: str, body_chars: int = 8000) -> str:
    """One captured exchange in full (credentials in headers are redacted)."""
    return await _engagement_call(
        "capture", "http_capture", capture_id=capture_id, body_chars=body_chars
    )


@tool
async def http_captures(host: str = "", probe: str = "", limit: int = 20) -> str:
    """Recent captures, newest first, optionally for one host or probe."""
    return await _engagement_call("capture", "http_captures", host=host, probe=probe, limit=limit)


@tool
async def capture_verify(capture_id: str, expect_host: str = "") -> str:
    """Whether a capture exists for this engagement, is in scope and is for expect_host."""
    return await _engagement_call(
        "capture", "capture_verify", capture_id=capture_id, expect_host=expect_host
    )


@tool
async def probe_list() -> str:
    """The deterministic probes available: vulnerability class, what each checks, parameters."""
    return await call_mcp("capture", "probe_list", {})


@tool
async def probe_run(probe: str, params_json: str) -> str:
    """Run a deterministic probe (jwt_alg_none, idor, ssrf_canary, numeric_boundary,
    mass_assignment, graphql_checks, sqli, xss_reflected, ssti, command_injection,
    open_redirect, path_traversal, cors). You choose the endpoint and identities; the probe sends
    the requests, compares the outcomes and returns vulnerable true / false / null (null =
    could not tell) with evidence capture ids. params_json is a JSON object (see probe_list).
    A state-changing probe may return APPROVAL_REQUIRED with a request_id: nothing was sent;
    after the operator allows it, call again with identical params_json (one approval, one run).
    Add "identity": "<name from identities_list>" to params_json to run the whole probe signed in
    as that test account (not for idor and jwt_alg_none, which take their own credentials)."""
    return await _engagement_call("capture", "probe_run", probe=probe, params_json=params_json)


@tool
async def recipe_check(recipe_json: str) -> str:
    """Check a recipe without sending anything. When no probe fits a lead, describe the check
    as data: recipe_json is {"name": slug, "class": vulnerability class, "title", "endpoint":
    the URL the finding is about, "parameter" (optional), "remediation": what the owner should
    change, "steps": [1-12 of {"id": slug, "method": GET|HEAD|POST|PUT|PATCH|DELETE, "url"
    (literal host), "headers", "body" (string, or object sent as JSON), "identity": a test
    account or "" for none, "extract": {"var": {"from": "json"|"header"|"regex"|"status",
    "path"|"name"|"pattern": ...}}, "expect": {"status", "body_contains",
    "body_not_contains"}}], "verdict": {"vulnerable_if": [conditions], "control": [at least
    one condition showing the normal behaviour]}}. A condition is {"step": id} plus one of
    "status", "body_contains", "body_not_contains", "same_as": id, "differs_from": id, or
    "json": dotted path with "equals"|"gt"|"lt". {{var}} is a value extracted by an earlier
    step; {{rand}} and {{ts}} are built in; pipes: |urlencode |b64 |b64url |json |lower
    |upper. Returns ok with state_changing and the step count, or errors with exact paths."""
    return await _engagement_call("capture", "recipe_check", recipe_json=recipe_json)


@tool
async def recipe_run(recipe_json: str) -> str:
    """Run a recipe through the evidence gateway (scope, approval hold, rate limit and ledger
    apply to every step), or a saved one with {"use": "<name>"}. Returns vulnerable true /
    false / null, outcome (vulnerable, not_vulnerable, precondition_failed, control_failed,
    not_sent), a summary and capture ids per step; extracted values are never returned. A
    failed expect stops the run as precondition_failed: that is not a finding. A recipe with
    any POST/PUT/PATCH/DELETE step may return APPROVAL_REQUIRED: one approval covers one run of
    that exact recipe. A positive result is queued (finding_id); finding_verify re-runs it."""
    return await _actor_call("recipe_run", recipe_json=recipe_json)


@tool
async def recipe_save(recipe_json: str) -> str:
    """Save a valid recipe under its name so it can be run again with {"use": "<name>"}."""
    return await _actor_call("recipe_save", recipe_json=recipe_json)


@tool
async def recipe_list() -> str:
    """Recipes saved for this engagement: name, class, title, endpoint, last outcome."""
    return await _engagement_call("capture", "recipe_list")


@tool
async def recipe_get(name: str) -> str:
    """One saved recipe in full."""
    return await _engagement_call("capture", "recipe_get", name=name)


# ── scope ────────────────────────────────────────────────────────────


@tool
async def scope_show() -> str:
    """The enforced scope for this engagement: in/out-of-scope rules, rate limits, whether
    state-changing requests need approval, banned techniques."""
    return await _engagement_call("scope", "scope_show")


@tool
async def scope_check(target: str) -> str:
    """Is this host, host:port or URL in the enforced scope? Returns the reason if not."""
    return await _engagement_call("scope", "scope_check", target=target)


@tool
async def program_info() -> str:
    """The bounty program's official scope data and binding rules, as imported by the operator:
    rate limit, banned techniques (no DoS, no social engineering, no data exfiltration beyond
    proof), excluded classes, and what a finding must contain. Read it before testing."""
    return await _engagement_call("scope", "program_info")


# ── browser ──────────────────────────────────────────────────────────


@tool
async def browser_open(url: str) -> str:
    """Open an in-scope URL in a real browser (JavaScript runs). Requests the page makes to
    out-of-scope hosts are blocked and reported."""
    return await _engagement_call("browser", "browser_open", url=url)


@tool
async def browser_click(selector: str) -> str:
    """Click the element matching a CSS selector in the open page."""
    return await _engagement_call("browser", "browser_click", selector=selector)


@tool
async def browser_fill(selector: str, text: str) -> str:
    """Type text into the input matching a CSS selector."""
    return await _engagement_call("browser", "browser_fill", selector=selector, text=text)


@tool
async def browser_eval(expression: str) -> str:
    """Evaluate a JavaScript expression in the open page and return its JSON value."""
    return await _engagement_call("browser", "browser_eval", expression=expression)


@tool
async def browser_text() -> str:
    """The visible text of the open page."""
    return await _engagement_call("browser", "browser_text")


@tool
async def browser_html() -> str:
    """The rendered HTML of the open page (after scripts ran)."""
    return await _engagement_call("browser", "browser_html")


@tool
async def browser_requests(limit: int = 50) -> str:
    """Requests the open page made: allowed ones, and blocked ones with the reason."""
    return await _engagement_call("browser", "browser_requests", limit=limit)


@tool
async def browser_cookies() -> str:
    """Cookie names and security flags for the browser session (values are not returned)."""
    return await _engagement_call("browser", "browser_cookies")


# ── findings, queue, evidence ────────────────────────────────────────


async def _actor_call(tool_name: str, **arguments: Any) -> str:
    """A capture-server call that records who acted. The actor comes from the run."""
    return await _engagement_call("capture", tool_name, actor=current_actor(), **arguments)


@tool
async def candidates_next(limit: int = 5) -> str:
    """The next leads to prove, most promising first: scanner hits, recon leads, probe
    results and access-control mismatches, deduplicated. They are claimed for you for a
    while so two agents do not work the same lead. Start testing from this list."""
    return await _actor_call("candidates_next", limit=limit)


@tool
async def leads_ruled_out(query: str = "") -> str:
    """What was already tried here and dropped, with the reason, when and by whom: the probe
    said not vulnerable, the gateway blocked it (its code), the operator refused the
    approval, the verifier could not re-prove it (its reasons), the grader discarded it
    (the rule). Do not repeat a ruled-out technique at the same endpoint and parameter.
    failed_attempts (timeouts, rate limits, a lost login) retired nothing and may be
    retried. query filters by words in the technique, endpoint, parameter or reason."""
    return await _engagement_call("capture", "leads_ruled_out", query=query)


@tool
async def findings_chains() -> str:
    """What each proven finding gives an attacker (another user's session, the admin role,
    any file, SSRF to internal hosts...) and what it needs first (a logged-in user, other
    users' ids...), and the possible chains where one gives what another needs. A chain is
    a lead to test, never a proven finding; open_needs says what no finding gives yet."""
    return await _engagement_call("capture", "findings_chains")


@tool
async def findings_due() -> str:
    """Decisions whose review date has passed: leads ruled out a while ago (they are back in
    candidates_next) and findings graded hold or discard. Worth a fresh look; only the
    operator extends or closes them."""
    return await _engagement_call("capture", "findings_due")


@tool
async def finding_submit(finding_json: str) -> str:
    """Record a claim. finding_json: title, class, severity, endpoint, method, parameter,
    description, remediation (what the owner should change), source, invariant (the rule it
    breaks, e.g. "a user can only read their own basket"), entry_point (the request a user
    can reach first, e.g. "GET https://app/api/basket/1"), and assertions:
    [{capture_id, identity, expect: {status, body_contains, body_not_contains, differs_from,
    same_as}}]. invariant and entry_point are required for access_control, business_logic
    and auth_session. Cite captures made against the endpoint you name. A claim is a
    candidate until finding_verify proves it."""
    return await _actor_call("finding_submit", finding_json=finding_json)


@tool
async def finding_verify(finding_id: str) -> str:
    """Have the independent verifier re-prove a finding: it re-runs the probe the finding
    came from, or re-sends the cited captures and checks your assertions. Only this makes a
    finding exploit_verified. Read the reasons when it comes back inconclusive."""
    return await _engagement_call("capture", "finding_verify", finding_id=finding_id)


@tool
async def finding_get(finding_id: str) -> str:
    """One finding with its verification, grade and history."""
    return await _engagement_call("capture", "finding_get", finding_id=finding_id)


@tool
async def findings_list(status: str = "", grade: str = "") -> str:
    """Findings of this engagement by status (candidate, exploit_verified, inconclusive,
    discarded) or grade (submit, hold, discard)."""
    return await _engagement_call("capture", "findings_list", status=status, grade=grade)


@tool
async def finding_grade(finding_id: str) -> str:
    """Grade a verified finding against the program's rules: submit, hold or discard, with
    the reasons and what would have to change. Scanner-known issues are taken into account."""
    engagement = current_engagement()
    if not engagement:
        return json.dumps({"error": "no engagement is active for this run"})
    known: list[Any] = []
    if server_url("recon"):
        raw = await call_mcp(
            "recon",
            "recon_query",
            {"engagement": engagement, "record_type": "vulnerability", "limit": 200},
        )
        try:
            known = list((json.loads(raw) or {}).get("records") or [])
        except (TypeError, ValueError):
            known = []
    return await call_mcp(
        "capture",
        "finding_grade",
        {
            "engagement": engagement,
            "finding_id": finding_id,
            "known_issues_json": json.dumps(known),
        },
    )


@tool
async def report_build(fmt: str = "markdown") -> str:
    """The engagement report as markdown, html or json. Only verified findings are listed
    as findings; candidates and inconclusive items appear as not proven."""
    return await _engagement_call("capture", "report_build", fmt=fmt)


@tool
async def evidence_export(finding_id: str = "", capture_ids_json: str = "") -> str:
    """A redacted evidence bundle for a finding or a list of captures: HAR, a curl script
    that reproduces the requests, and a manifest with hashes. Written for the operator."""
    return await _engagement_call(
        "capture", "evidence_export", capture_ids_json=capture_ids_json, finding_id=finding_id
    )


@tool
async def identities_list() -> str:
    """Test accounts the operator declared for this engagement: name, role and what each
    owns. Use a name as identity=... in http_send. Secrets are never shown."""
    return await _engagement_call("capture", "identities_list")


@tool
async def authz_matrix_run(
    urls_json: str,
    identities_json: str = "",
    owners_json: str = "",
    max_requests: int = 120,
    inferred_json: str = "",
) -> str:
    """Access-control check without guessing: request each URL (GET/HEAD only) as every
    declared identity and as nobody, and report which objects are readable by someone who
    does not own them. urls_json is a list of URLs; owners_json maps url -> identity name.
    inferred_json lists the URLs of owners_json whose owner was inferred from a crawl
    rather than declared; those are reported only when the owner's marker leaks.
    Mismatches are queued as candidates."""
    extra = {"inferred_json": inferred_json} if inferred_json else {}
    return await _engagement_call(
        "capture",
        "authz_matrix_run",
        urls_json=urls_json,
        identities_json=identities_json,
        owners_json=owners_json,
        max_requests=max_requests,
        **extra,
    )


@tool
async def surface_crawl(seeds_json: str, identity: str = "", max_requests: int = 120) -> str:
    """Map what a page tree exposes, signed in when identity names a test account from
    identities_list. Follows same-host links breadth-first from seeds_json (a JSON list of
    absolute URLs), GET only, at most max_requests requests (1-300). It never requests a
    logout, delete, reset, export or similar URL, and records forms without submitting them.
    Returns the pages it fetched (capture ids), every same-host URL it saw, the forms, and
    what it skipped and why."""
    return await _engagement_call(
        "capture",
        "surface_crawl",
        seeds_json=seeds_json,
        identity=identity,
        max_requests=max_requests,
    )


# ── lessons and the shared board ─────────────────────────────────────


@tool
async def memory_search(
    query: str = "", classes_json: str = "", technologies_json: str = "", kind: str = ""
) -> str:
    """Lessons from earlier engagements that match a technology or bug class (JSON lists).
    Verified lessons come first. Check before testing a familiar stack."""
    return await _engagement_call(
        "capture",
        "memory_search",
        query=query,
        classes_json=classes_json,
        technologies_json=technologies_json,
        kind=kind,
    )


@tool
async def memory_save(lesson_json: str) -> str:
    """Save a reusable lesson for future engagements. lesson_json: kind (guide, failure or
    payload), title, body, classes, technologies, finding_id. Describe the technique, not the target: secrets and
    target names are removed. It is trusted only if finding_id is a verified finding."""
    return await _actor_call("memory_save", lesson_json=lesson_json)


@tool
async def facts_list() -> str:
    """The shared board for this engagement: facts other agents recorded, open work nobody
    has claimed, and hints. Read it before starting something."""
    return await _engagement_call("capture", "facts_list")


@tool
async def fact_add(text: str, evidence_json: str = "") -> str:
    """Record an observation on the shared board (append-only). evidence_json is a list of
    capture ids or record ids that support it."""
    return await _actor_call("fact_add", text=text, evidence_json=evidence_json)


@tool
async def intent_open(text: str, from_facts_json: str) -> str:
    """Open a piece of work that follows from facts on the board (from_facts_json: list of
    fact ids). Others can then claim it."""
    return await _actor_call("intent_open", text=text, from_facts_json=from_facts_json)


@tool
async def intent_claim(intent_id: str) -> str:
    """Claim a piece of open work, or renew your claim while you are still on it. A live
    claim by another agent is refused: pick something else."""
    return await _actor_call("intent_claim", intent_id=intent_id)


@tool
async def intent_conclude(
    intent_id: str, fact_text: str, evidence_json: str = "", abandon: bool = False
) -> str:
    """Finish work you claimed by stating the fact it produced, or abandon it with the
    reason (abandon=true) so someone else can take it."""
    return await _actor_call(
        "intent_conclude",
        intent_id=intent_id,
        fact_text=fact_text,
        evidence_json=evidence_json,
        abandon=abandon,
    )


@tool
async def hints_list() -> str:
    """Guidance left on the board by the operator or other agents."""
    return await _engagement_call("capture", "hints_list")


@tool
async def hint_add(text: str) -> str:
    """Leave a short hint for other agents on the board."""
    return await _actor_call("hint_add", text=text)


@tool
async def recon_coverage(asset: str = "") -> str:
    """What recon did and did not check, per asset and stage. An absent stamp means "not
    checked", never "clean". Use it before concluding an asset has nothing to test."""
    return await _engagement_call("recon", "recon_coverage", asset=asset)


_BY_SERVER: dict[str, list[Any]] = {
    "recon": [
        recon_summary,
        recon_assets,
        recon_query,
        recon_record,
        recon_diff,
        recon_raw,
        recon_request_rerun,
        recon_rerun_status,
        recon_coverage,
    ],
    "capture": [
        http_send,
        http_replay,
        http_capture,
        http_captures,
        capture_verify,
        probe_list,
        probe_run,
        recipe_check,
        recipe_run,
        recipe_save,
        recipe_list,
        recipe_get,
        candidates_next,
        leads_ruled_out,
        finding_submit,
        finding_verify,
        finding_get,
        findings_list,
        finding_grade,
        findings_chains,
        findings_due,
        report_build,
        evidence_export,
        identities_list,
        authz_matrix_run,
        surface_crawl,
        memory_search,
        memory_save,
        facts_list,
        fact_add,
        intent_open,
        intent_claim,
        intent_conclude,
        hints_list,
        hint_add,
    ],
    "scope": [scope_show, scope_check, program_info],
    "browser": [
        browser_open,
        browser_click,
        browser_fill,
        browser_eval,
        browser_text,
        browser_html,
        browser_requests,
        browser_cookies,
    ],
}

ALL_STACK_MCP_TOOLS: list[Any] = [t for tools in _BY_SERVER.values() for t in tools]


def stack_mcp_tools() -> list[Any]:
    """Tools for the servers that are configured in this process."""
    return [t for server, tools in _BY_SERVER.items() if server_url(server) for t in tools]


# Which servers each role gets. Everyone who plans or tests reads recon data
# and scope; only roles that actively test a target get the capture gateway
# and the browser.
_READERS = frozenset({"buggy", "recon", "analyst", "scout", "asvs", "mitre_attack"})
_TESTERS = frozenset(
    {
        "exploit",
        "api_security",
        "authn_session",
        "business_logic",
        "clientside_security",
        "graphql_security",
        "llm_security",
        "secrets_cicd",
        "ssrf_cloud",
    }
)


_READER_CAPTURE_TOOLS: tuple[Any, ...] = (
    findings_list,
    finding_get,
    leads_ruled_out,
    findings_chains,
    findings_due,
    report_build,
    identities_list,
    memory_search,
    facts_list,
    fact_add,
    intent_open,
    hints_list,
)


def stack_mcp_tools_for(role: str) -> list[Any]:
    """The configured stack MCP tools appropriate for ``role`` (empty for other roles).

    Roles that plan or test also get ``research_fetch`` (public reference pages,
    never the target), which needs no server.
    """
    research = [research_fetch] if web_enabled() else []
    if role in _TESTERS:
        servers = ("recon", "scope", "capture", "browser")
    elif role in _READERS:
        # Planning and analysis roles read the queue, the findings, the board and the
        # lessons; they do not send requests or run probes.
        tools = [
            t for server in ("recon", "scope") if server_url(server) for t in _BY_SERVER[server]
        ]
        if server_url("capture"):
            tools += list(_READER_CAPTURE_TOOLS)
        return tools + research
    else:
        return []
    return [t for server in servers if server_url(server) for t in _BY_SERVER[server]] + research


__all__ = [
    "ALL_STACK_MCP_TOOLS",
    "SERVER_ENV",
    "call_mcp",
    "current_actor",
    "current_engagement",
    "stack_mcp_tools",
    "stack_mcp_tools_for",
]
