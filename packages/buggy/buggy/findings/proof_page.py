"""Proof page: one proven finding's recorded exchange as a self-contained HTML document.

The scoped browser records this page as the finding's proof video
(``proof_record``). It is rendered offline: the requests on it were sent
through the evidence gateway when the finding was proved, the answers are the
target's real recorded responses, and nothing is sent to the target while the
page is shown or recorded. The first frame says so.

:func:`proof_html` reads one entry of a report's ``findings`` list
(:func:`buggy.findings.report.build`): its ``reproduction`` steps, each with
``request``, ``response``, ``payload`` and ``highlight``; a finding with no
assertions falls back to its ``proof`` (replay) entries.

Everything that came from the target or an agent is escaped and shown as text:
a stored XSS payload in a response is displayed, never executed. The document
carries inline CSS only: no script, no event handler, no external resource.
Standard library only; the same input gives the same bytes.
"""

from __future__ import annotations

import html
import json
import re
from typing import Any
from urllib.parse import quote, quote_plus

#: The sentence on the first frame of every proof video.
RECORDED_NOTE = (
    "Recorded evidence: the requests below were sent through the evidence gateway and the "
    "answers are the target's real responses; nothing is sent to the target while this is "
    "recorded."
)
#: Characters of a request or response body shown, around the payload or the proving text.
MAX_BODY_CHARS = 2400

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

_CSS = """
*{box-sizing:border-box}
body{margin:0;background:#ffffff;color:#1b1f24;font:16px/1.45 system-ui,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:0 32px}
section{min-height:700px;padding:28px 0;border-bottom:2px solid #d0d7de}
.card h1{font-size:30px;margin:8px 0 16px}
.notice{border:2px solid #9a6700;background:#fff8c5;padding:14px 18px;border-radius:6px;
font-weight:600}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:18px 0}
dt{color:#57606a}dd{margin:0;overflow-wrap:anywhere}
h2{font-size:24px;margin:0 0 8px}h3{font-size:17px;margin:16px 0 6px;color:#57606a}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;padding:10px 12px;border:1px solid #d0d7de;
border-radius:6px;background:#f6f8fa;font:14px/1.4 ui-monospace,Consolas,monospace}
mark.payload{background:#ffd8b5;color:#6e2a00;outline:2px solid #e16f24;border-radius:2px}
mark.match{background:#aceebb;color:#04260f;outline:2px solid #1a7f37;border-radius:2px}
.cut{color:#57606a;font-style:italic}
.meta{color:#57606a;font-size:14px;overflow-wrap:anywhere}
.status{font-weight:700}
""".strip()


def _s(value: Any) -> str:
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return _CONTROL.sub("�", text.replace("\r\n", "\n"))


def _h(value: Any) -> str:
    return html.escape(_s(value), quote=True)


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else 0


def _marked(text: str, needles: list[tuple[str, str]]) -> str:
    """``text`` escaped, with every occurrence of a needle wrapped in ``<mark class=...>``.

    ``needles`` are ``(text, css class)``. The needles of the first class given
    are marked first (the proving text wins over a payload that contains it);
    the next class is marked in what is left, and so on. Within a class the
    longest needle wins.
    """
    order = list(dict.fromkeys(css for needle, css in needles if needle))
    if not order:
        return _h(text)
    css = order[0]
    wanted = sorted({n for n, c in needles if n and c == css}, key=lambda n: (-len(n), n))
    rest = [(n, c) for n, c in needles if n and c != css]
    pattern = re.compile("|".join(re.escape(needle) for needle in wanted))
    out: list[str] = []
    last = 0
    for found in pattern.finditer(text):
        out.append(_marked(text[last : found.start()], rest))
        out.append(f'<mark class="{css}">{_h(found.group(0))}</mark>')
        last = found.end()
    out.append(_marked(text[last:], rest))
    return "".join(out)


def _cut(text: str, needles: list[str], limit: int = MAX_BODY_CHARS) -> tuple[str, int, int]:
    """``(window, bytes cut before, bytes cut after)``: ``text`` cut around the first needle."""
    if len(text) <= limit:
        return text, 0, 0
    found = [text.index(n) for n in needles if n and n in text]
    start = max(0, min(min(found) - limit // 3, len(text) - limit)) if found else 0
    end = start + limit
    return (
        text[start:end],
        len(text[:start].encode("utf-8", "replace")),
        len(text[end:].encode("utf-8", "replace")),
    )


def _cut_marker(count: int) -> str:
    return f'<span class="cut">[… {count} bytes not shown …]</span>' if count > 0 else ""


def _body_block(text: str, needles: list[tuple[str, str]], before: int, after: int) -> str:
    window, cut_before, cut_after = _cut(text, [n for n, _c in needles])
    before, after = before + cut_before, after + cut_after
    parts = []
    if before:
        parts.append(_cut_marker(before) + "\n")
    parts.append(_marked(window, needles))
    if after:
        parts.append("\n" + _cut_marker(after))
    return "".join(parts)


def _payload_forms(payload: str) -> list[str]:
    """The ways a payload appears in a recorded URL or body."""
    if not payload:
        return []
    forms = [payload, quote(payload, safe=""), quote(payload), quote_plus(payload)]
    forms.append(json.dumps(payload)[1:-1])
    return [form for form in dict.fromkeys(forms) if form]


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def proof_steps(finding: dict[str, Any]) -> list[dict[str, Any]]:
    """The steps a proof page shows: the reproduction steps, else the replay entries."""
    steps = [s for s in finding.get("reproduction") or [] if isinstance(s, dict)]
    if steps:
        return steps
    out = []
    for number, proof in enumerate(
        (p for p in finding.get("proof") or [] if isinstance(p, dict)), start=1
    ):
        out.append(
            {
                **proof,
                "number": number,
                "shows": _s(proof.get("status_line")),
                "replayed": True,
            }
        )
    return out


def _request_text(request: dict[str, Any], payload_marks: list[tuple[str, str]]) -> str:
    line = f"{_h(request.get('method'))} {_marked(_s(request.get('url')), payload_marks)}"
    headers = _dict(request.get("headers"))
    lines = [line] + [f"{_h(name)}: {_h(headers[name])}" for name in sorted(headers, key=str)]
    out = "\n".join(lines)
    body = _s(request.get("body"))
    before, after = _int(request.get("omitted_before")), _int(request.get("omitted_after"))
    if body or before or after:
        out += "\n\n" + _body_block(body, payload_marks, before, after)
    return out


def _response_text(response: dict[str, Any], match_marks: list[tuple[str, str]]) -> str:
    status = response.get("status")
    if isinstance(status, int) and not isinstance(status, bool):
        line = f'<span class="status">HTTP {status}</span>'
    else:
        line = f'<span class="status">no response</span> {_h(response.get("error"))}'.rstrip()
    headers = _dict(response.get("headers"))
    lines = [line] + [f"{_h(name)}: {_h(headers[name])}" for name in sorted(headers, key=str)]
    out = "\n".join(lines)
    body = _s(response.get("body"))
    before, after = _int(response.get("omitted_before")), _int(response.get("omitted_after"))
    if body or before or after:
        out += "\n\n" + _body_block(body, match_marks, before, after)
    return out


def _step(step: dict[str, Any], number: int, total: int) -> str:
    payload = _s(step.get("payload"))
    payload_marks = [(form, "payload") for form in _payload_forms(payload)]
    highlight = [_s(n) for n in step.get("highlight") or [] if _s(n)]
    response = _dict(step.get("response"))
    if _s(response.get("match")) and _s(response.get("match")) not in highlight:
        highlight.append(_s(response.get("match")))
    match_marks = [(n, "match") for n in highlight] + payload_marks
    parts = [f'<section class="step" id="step-{number}">']
    parts.append(f"<h2>Step {number} of {total}</h2>")
    shows = _s(step.get("shows")) or _s(step.get("text"))
    parts.append(f"<p><strong>What it shows:</strong> {_h(shows)}</p>")
    identity = _s(step.get("identity"))
    who = f"as the test account {identity!r}" if identity else "with no named test account"
    outcome = _s(step.get("outcome"))
    detail = f"Sent {who}" + (f"; verifier outcome: {outcome}" if outcome else "") + "."
    if _s(step.get("note")):
        detail += f" Note: {_s(step.get('note'))}"
    parts.append(f'<p class="meta">{_h(detail)}</p>')
    if payload:
        parts.append(f'<h3>Payload</h3><pre><mark class="payload">{_h(payload)}</mark></pre>')
    request = _dict(step.get("request"))
    if request:
        parts.append(f"<h3>Request</h3><pre>{_request_text(request, payload_marks)}</pre>")
    if response:
        label = "the verifier's replay" if step.get("replayed") else "as recorded"
        parts.append(f"<h3>Response ({_h(label)})</h3>")
        parts.append(f"<pre>{_response_text(response, match_marks)}</pre>")
    elif _s(step.get("excerpt")):
        parts.append(f"<h3>Response</h3><pre>{_marked(_s(step.get('excerpt')), match_marks)}</pre>")
    if not request and not response:
        parts.append("<p>This capture is not available to the report.</p>")
    meta = []
    if _s(step.get("capture_id")):
        meta.append(f"request capture {_s(step.get('capture_id'))}")
    if _s(request.get("sha256")):
        meta.append(f"request sha256 {_s(request.get('sha256'))}")
    if _s(response.get("capture_id")) and response.get("capture_id") != step.get("capture_id"):
        meta.append(f"response capture {_s(response.get('capture_id'))}")
    sha = _s(step.get("sha256")) or _s(response.get("sha256"))
    if sha:
        meta.append(f"response sha256 {sha}")
    if meta:
        parts.append(f'<p class="meta">{_h(" · ".join(meta))}</p>')
    parts.append("</section>")
    return "".join(parts)


def proof_html(finding: dict[str, Any], *, engagement: str, generated_at: str) -> str:
    """One self-contained HTML document showing ``finding``'s recorded proof, step by step.

    Sections are ``#title`` and ``#step-1`` … ``#step-N``. No script, no event
    handler, no external resource; every value from the target is escaped text.
    """
    item = finding if isinstance(finding, dict) else {}
    steps = proof_steps(item)
    fields = [
        ("Finding", item.get("id")),
        ("Severity", item.get("severity")),
        ("Class", item.get("class")),
        ("CWE", item.get("cwe") or "none given"),
        ("Endpoint", f"{_s(item.get('method'))} {_s(item.get('endpoint'))}".strip()),
        ("Parameter", item.get("parameter") or "none"),
        ("Engagement", engagement),
        ("Page generated", generated_at),
        ("Proof steps", str(len(steps))),
    ]
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">",
        f"<title>Proof {_h(item.get('id'))}</title>",
        f"<style>{_CSS}</style></head><body><main>",
        '<section class="card" id="title">',
        f"<h1>{_h(item.get('id'))}: {_h(item.get('title'))}</h1>",
        f'<p class="notice">{_h(RECORDED_NOTE)}</p>',
        "<dl>" + "".join(f"<dt>{_h(k)}</dt><dd>{_h(v)}</dd>" for k, v in fields) + "</dl>",
        "</section>",
    ]
    if not steps:
        parts.append(
            '<section id="step-1"><p>No proof step is recorded for this finding.</p></section>'
        )
    for number, step in enumerate(steps, start=1):
        parts.append(_step(step, number, len(steps)))
    parts.append("</main></body></html>")
    return "\n".join(parts) + "\n"


__all__ = ["MAX_BODY_CHARS", "RECORDED_NOTE", "proof_html", "proof_steps"]
