"""Server-side template injection and OS command injection probes.

Both probes confirm that ONE named parameter is evaluated (by a template
engine) or executed (by a shell) with canaries that do nothing: a
multiplication of two random 4-digit integers, and a bounded 3-second wait.
Nothing is read, written or deleted, no shell is opened and no out-of-band
channel is used. Every payload is a constant in this module; ``a*b`` in a
payload stands for the two integers of the run.

``ssti`` (never more than ``SSTI_MAX_REQUESTS``):

1. the valid value twice (baseline, and proof that the page is stable);
2. one arithmetic canary per engine family, appended to the valid value. A
   family is a candidate when the product appears in the response and the
   expression text does not;
3. for the first candidate, the control: the valid value followed by the
   plain digits of a different random number. The product must not appear.

``command_injection`` (never more than ``CMD_MAX_REQUESTS``):

1. the valid value twice;
2. output: one separator per request with an arithmetic echo, judged like the
   template canaries and confirmed by the same plain-digits control;
3. time (unless ``allow_time`` is false): one bounded wait per request; a
   slow answer is confirmed by the same payload with a zero wait.

A positive verdict always rests on a control request that rules out
coincidence; anything the probe could not attribute is reported as
``vulnerable: null``.

The gateway holds requests for approval by HTTP method. A shell payload is
state-changing whatever the method, so ``command_injection`` does not send
its payloads over GET / HEAD / OPTIONS while the engagement requires approval
for state-changing requests.
"""

from __future__ import annotations

import html
import secrets
from dataclasses import dataclass
from typing import Any

from buggy.capture.gateway import SAFE_METHODS, GatewayRefusal
from buggy.capture.probes.base import Context, ProbeResult, similarity, text
from buggy.capture.probes.injection import (
    CONTROL_MAX_EXTRA_MS,
    DELAY_MIN_EXTRA_MS,
    DELAY_SECONDS,
    STABLE_SIMILARITY,
    _BudgetExceeded,
    _failed,
    _outcome,
    _Run,
    _Target,
)
from buggy.capture.store import Capture

VULN_CLASS = "injection"

SSTI_PROBE = "ssti"
SSTI_CWE = "CWE-1336"
SSTI_MAX_REQUESTS = 8  # 2 baselines + 5 canaries + 1 control
SSTI_REMEDIATION = (
    "Never build a template from request data: keep templates static and pass user input to "
    "the engine only as data (context variables). Where users must supply templates, use a "
    "logic-less or sandboxed engine and keep it patched."
)

CMD_PROBE = "command_injection"
CMD_CWE = "CWE-78"
CMD_MAX_REQUESTS = 11  # 2 baselines + 5 output + 3 time + 1 control
CMD_REMEDIATION = (
    "Do not pass request data to a shell: call the program directly with an argument list (no "
    "system(), no shell=True, no backticks) or use a library instead of a command. Validate "
    "the value against a strict allow-list; escaping shell metacharacters alone is fragile."
)

# The text in a payload that stands for the multiplication of the run's two integers.
EXPRESSION = "a*b"

# One arithmetic canary per template engine family, in the order they are sent.
SSTI_CANARIES: tuple[tuple[str, str], ...] = (
    ("jinja2_twig", "{{a*b}}"),  # Jinja2, Twig, Nunjucks, Handlebars-like
    ("el_freemarker", "${a*b}"),  # Java EL, FreeMarker, Thymeleaf, Mako
    ("erb_ejs", "<%= a*b %>"),  # ERB, EJS, JSP scriptlet expressions
    ("ruby_pug", "#{a*b}"),  # Ruby interpolation, Pug, Slim
    ("smarty", "{a*b}"),  # Smarty and other single-brace engines
)
# A single-brace engine evaluates the inside of ``{{a*b}}`` and keeps the outer braces.
_OUTER_FAMILY, _INNER_FAMILY = "jinja2_twig", "smarty"

# Shell separators with an arithmetic echo. The last one is the cmd.exe form.
OUTPUT_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("semicolon", ";echo $((a*b))"),
    ("pipe", "|echo $((a*b))"),
    ("backtick", "`echo $((a*b))`"),
    ("subshell", "$(echo $((a*b)))"),
    ("windows_ampersand", "& set /a a*b"),
)

# ``(name, payload that waits DELAY_SECONDS, the same payload with no wait)``.
# The ping form is for cmd.exe, where four echo requests take three seconds.
# ``-w 3`` is there for the other systems: an iputils ping reads ``-n 4 host``
# as a route and would never stop; with ``-w 3`` it gives up after three
# seconds. cmd.exe reads it as a 3 ms reply timeout, which changes nothing.
TIME_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("semicolon", f";sleep {DELAY_SECONDS}", ";sleep 0"),
    ("pipe", f"|sleep {DELAY_SECONDS}", "|sleep 0"),
    ("windows_ampersand", "& ping -n 4 -w 3 127.0.0.1", "& ping -n 1 -w 3 127.0.0.1"),
)


# ── the numbers of one run ───────────────────────────────────────────


def _four_digits() -> int:
    """A random 4-digit integer."""
    return 1000 + secrets.randbelow(9000)


def _other_number(digits: int) -> int:
    """A random integer with exactly ``digits`` digits."""
    low = 10 ** (digits - 1)
    return low + secrets.randbelow(9 * low)


@dataclass(frozen=True, slots=True)
class _Numbers:
    """Two random 4-digit integers, and the unrelated number the control sends."""

    a: int
    b: int
    control: int

    @classmethod
    def draw(cls, value: Any) -> _Numbers:
        while True:
            a, b = _four_digits(), _four_digits()
            product = str(a * b)
            control = _other_number(len(product))
            # The control request itself must not spell the product.
            if product not in f"{value}{control}":
                return cls(a, b, control)

    @property
    def product(self) -> str:
        return str(self.a * self.b)

    @property
    def expression(self) -> str:
        return f"{self.a}*{self.b}"

    def fill(self, payload: str) -> str:
        return payload.replace(EXPRESSION, self.expression)

    def to_dict(self) -> dict[str, Any]:
        return {"a": self.a, "b": self.b, "product": self.a * self.b, "control": self.control}


def _read(capture: Capture, numbers: _Numbers) -> tuple[bool, bool]:
    """``(the product appears, the expression came back as text)`` for one response."""
    body = text(capture)
    # The multiplication is in every payload, so finding it (entity-encoded or
    # not) is finding the payload, however the characters around it were treated.
    reflected = numbers.expression in body or numbers.expression in html.unescape(body)
    return numbers.product in body, reflected


# ── request bookkeeping ──────────────────────────────────────────────


@dataclass
class _ExecRun(_Run):
    """C1's request bookkeeping with a per-probe identity, bound and result layout."""

    probe: str = ""
    cwe: str = ""
    remediation: str = ""
    bound: int = 0

    @property
    def left(self) -> int:
        return self.bound - len(self.evidence)

    def result(self, vulnerable: bool | None, summary: str) -> ProbeResult:
        details: dict[str, Any] = {
            "technique": self.technique,
            "method": self.target.method,
            "location": self.target.location,
            "parameter": self.target.parameter,
            "requests_sent": len(self.evidence),
            "max_requests": self.bound,
            "captures": dict(self.captures),
            "payloads": dict(self.payloads),
            **self.info,
        }
        if self.unresolved:
            details["unresolved"] = list(self.unresolved)
        return ProbeResult(
            self.probe,
            VULN_CLASS,
            self.cwe,
            vulnerable,
            summary,
            list(self.evidence),
            details,
            self.remediation,
        )


def _guarded(run: _ExecRun, examine: Any, *args: Any) -> ProbeResult:
    try:
        return examine(run, *args)
    except GatewayRefusal as refusal:
        run.info["refusal"] = refusal.to_dict()
        return run.result(
            None,
            f"the gateway refused a request ({refusal.code}) after {len(run.evidence)} sent; "
            "cannot tell",
        )
    except _BudgetExceeded as exc:
        return run.result(
            None, f"the request bound ({run.bound}) was reached before {exc}; cannot tell"
        )


def _baseline(run: _ExecRun) -> float | ProbeResult:
    """Send the valid value twice. The slower time in ms, or the "cannot tell" result."""
    value = run.target.value
    first = run.send("baseline", value, "baseline (valid value)")
    if _failed(first):
        return run.result(
            None, f"the baseline request failed ({_outcome(first)}); nothing to compare against"
        )
    second = run.send("baseline_repeat", value, "baseline repeated (is the page stable?)")
    stability = similarity(first, second)
    baseline_ms = max(first.elapsed_ms, second.elapsed_ms)
    run.info["baseline"] = {
        "status": first.status,
        "repeat_status": second.status,
        "similarity": stability,
        "elapsed_ms": round(baseline_ms, 1),
    }
    if _failed(second) or second.status != first.status or stability < STABLE_SIMILARITY:
        return run.result(
            None,
            "the page is unstable: two identical requests answered differently "
            f"({_outcome(first)} / {_outcome(second)}, similarity {stability}); cannot compare",
        )
    return baseline_ms


def _arithmetic(
    run: _ExecRun,
    numbers: _Numbers,
    payloads: tuple[tuple[str, str], ...],
    role: str,
    tried: list[dict[str, Any]],
) -> tuple[str, Capture] | ProbeResult | None:
    """Send the arithmetic payloads until one is evaluated and the control confirms it.

    Returns ``(name, capture)`` of the confirmed payload, a "cannot tell"
    result when the control could not rule out coincidence, or ``None`` when
    no payload was a candidate.
    """
    target = run.target
    for name, template in payloads:
        payload = numbers.fill(template)
        capture = run.send(f"{role}_{name}", target.inject(payload), f"{name}: {template}")
        entry: dict[str, Any] = {"name": name, "payload": payload, "status": capture.status}
        tried.append(entry)
        if capture.error:
            entry["outcome"] = "no_answer"
            run.unresolved.append(f"the {name} request got no answer")
            continue
        product_present, reflected = _read(capture, numbers)
        entry["product_present"], entry["payload_reflected"] = product_present, reflected
        if not product_present:
            entry["outcome"] = "reflected_as_text" if reflected else "not_evaluated"
            continue
        if reflected:
            entry["outcome"] = "ambiguous"
            run.unresolved.append(
                f"{name}: the product {numbers.product} appears, but so does the text of the "
                "expression, so this response does not count as proof"
            )
            continue
        control = run.send(
            f"{role}_control",
            target.inject(str(numbers.control)),
            "plain digits of another number (control)",
        )
        entry["control_status"] = control.status
        if control.error:
            entry["outcome"] = "control_no_answer"
            return run.result(
                None,
                f"{name}: the product {numbers.product} appeared, but the control request got "
                "no answer; cannot tell",
            )
        if numbers.product in text(control):
            entry["outcome"] = "coincidence"
            return run.result(
                None,
                f"the number {numbers.product} also appears when {target.parameter!r} carries "
                "plain digits and no expression: it is part of the page, not the result of an "
                "evaluation. Run the probe again for different numbers; cannot tell",
            )
        entry["outcome"] = "evaluated"
        return name, capture
    return None


# ── ssti ─────────────────────────────────────────────────────────────


def ssti(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Is one named parameter evaluated as a server-side template expression?"""
    run = _ExecRun(
        ctx,
        _Target.from_params(params),
        probe=SSTI_PROBE,
        cwe=SSTI_CWE,
        remediation=SSTI_REMEDIATION,
        bound=SSTI_MAX_REQUESTS,
    )
    run.info["engine_family"] = None
    return _guarded(run, _examine_ssti)


def _examine_ssti(run: _ExecRun) -> ProbeResult:
    target = run.target
    baseline = _baseline(run)
    if isinstance(baseline, ProbeResult):
        return baseline

    numbers = _Numbers.draw(target.value)
    run.info["numbers"] = numbers.to_dict()
    run.info["canaries"] = []
    found = _arithmetic(run, numbers, SSTI_CANARIES, "canary", run.info["canaries"])
    if isinstance(found, ProbeResult):
        return found
    if found is not None:
        family, capture = found
        if family == _OUTER_FAMILY and "{" + numbers.product + "}" in text(capture):
            family = _INNER_FAMILY
        run.technique, run.info["engine_family"] = "arithmetic", family
        return run.result(
            True,
            f"{target.parameter!r} is evaluated by a template engine ({family} syntax): "
            f"{numbers.expression} came back as {numbers.product}, the expression text did "
            "not, and the same request with plain digits does not contain that number",
        )
    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    return run.result(
        False,
        f"no template evaluation in {target.parameter!r}: none of the {len(SSTI_CANARIES)} "
        "arithmetic canaries came back as its product",
    )


# ── command injection ────────────────────────────────────────────────


def command_injection(ctx: Context, params: dict[str, Any]) -> ProbeResult:
    """Does one named parameter reach an OS shell?"""
    run = _ExecRun(
        ctx,
        _Target.from_params(params),
        probe=CMD_PROBE,
        cwe=CMD_CWE,
        remediation=CMD_REMEDIATION,
        bound=CMD_MAX_REQUESTS,
    )
    raw = params.get("allow_time")
    allow_time = not (raw is False or str(raw).strip().lower() == "false")
    run.info["allow_time"] = allow_time
    return _guarded(run, _examine_command, allow_time)


def _approval_hold(run: _ExecRun) -> dict[str, Any] | None:
    """Why the shell payloads may not be sent, or ``None`` when they may.

    The gateway holds POST / PUT / PATCH / DELETE itself. Over a method it
    lets through, the hold is kept here: a request that asks a shell to run
    something is state-changing whatever its method.
    """
    if run.target.method not in SAFE_METHODS:
        return None
    try:
        _scope, document = run.ctx.gateway.scope_for(run.ctx.engagement)
    except GatewayRefusal:
        return None  # the gateway reports this itself on the next send
    if not run.ctx.gateway.approval_required(document):
        return None
    return {
        "status": "refused",
        "code": "APPROVAL_REQUIRED",
        "held_by": "probe",
        "detail": (
            f"{CMD_PROBE} asks a shell to run a command, which is state-changing whatever the "
            f"HTTP method, and this engagement requires approval for state-changing requests. "
            f"The gateway only files approval requests for methods other than "
            f"{', '.join(sorted(SAFE_METHODS))}, so there is nothing to approve for a "
            f"{run.target.method}: no payload was sent. The operator can waive the approval "
            "for this engagement (approvals.state_changing: not_required)."
        ),
    }


def _examine_command(run: _ExecRun, allow_time: bool) -> ProbeResult:
    target = run.target
    baseline_ms = _baseline(run)
    if isinstance(baseline_ms, ProbeResult):
        return baseline_ms

    hold = _approval_hold(run)
    if hold is not None:
        run.info["refusal"] = hold
        return run.result(
            None,
            "approval is required before shell payloads are sent (APPROVAL_REQUIRED); only the "
            f"{len(run.evidence)} baseline requests were sent; cannot tell",
        )

    # 1. Output: an arithmetic echo behind each separator.
    numbers = _Numbers.draw(target.value)
    run.info["numbers"] = numbers.to_dict()
    run.info["output"] = []
    found = _arithmetic(run, numbers, OUTPUT_PAYLOADS, "output", run.info["output"])
    if isinstance(found, ProbeResult):
        return found
    if found is not None:
        name, _capture = found
        run.technique, run.info["separator"] = "output", name
        return run.result(
            True,
            f"{target.parameter!r} reaches a shell: the {name} payload made it compute "
            f"{numbers.expression} and print {numbers.product}, the payload text did not come "
            "back, and the same request with plain digits does not contain that number",
        )

    # 2. Time: a bounded wait, confirmed by the same payload with no wait.
    if allow_time:
        outcome = _time_signal(run, baseline_ms)
        if outcome is not None:
            return outcome

    if run.unresolved:
        return run.result(None, "cannot tell: " + "; ".join(run.unresolved))
    checked = "output and time" if allow_time else "output"
    return run.result(
        False,
        f"no command execution through {target.parameter!r}: the {checked} checks were all "
        "negative",
    )


def _time_signal(run: _ExecRun, baseline_ms: float) -> ProbeResult | None:
    """Try the bounded waits; a result ends the probe, ``None`` means negative."""
    target = run.target
    timing: dict[str, Any] = {
        "baseline_ms": round(baseline_ms, 1),
        "delay_seconds": DELAY_SECONDS,
        "tried": [],
    }
    run.info["time"] = timing
    for name, wait, no_wait in TIME_PAYLOADS:
        delayed = run.send(f"time_{name}", target.inject(wait), f"{name}: {wait}")
        extra = delayed.elapsed_ms - baseline_ms
        entry: dict[str, Any] = {"name": name, "payload": wait, "delay_extra_ms": round(extra, 1)}
        timing["tried"].append(entry)
        if delayed.error:
            run.unresolved.append(f"the {name} delay request got no answer; timing stopped")
            return None
        if extra < DELAY_MIN_EXTRA_MS:
            continue
        control = run.send(
            f"time_control_{name}", target.inject(no_wait), f"{name}: {no_wait} (control)"
        )
        control_extra = control.elapsed_ms - baseline_ms
        entry["control_payload"] = no_wait
        entry["control_extra_ms"] = round(control_extra, 1)
        if not control.error and control_extra <= CONTROL_MAX_EXTRA_MS:
            run.technique, run.info["separator"] = "time", name
            return run.result(
                True,
                f"{target.parameter!r} reaches a shell: the {name} payload ({wait.strip()}) "
                f"slows the response by {round(extra / 1000, 1)} s while the same payload with "
                f"no wait does not ({round(control_extra / 1000, 1)} s)",
            )
        return run.result(
            None,
            f"the {name} delay payload was slow (+{round(extra / 1000, 1)} s) but so was its "
            f"no-wait control (+{round(control_extra / 1000, 1)} s): timing is unreliable; "
            "cannot tell",
        )
    return None


__all__ = [
    "CMD_MAX_REQUESTS",
    "OUTPUT_PAYLOADS",
    "SSTI_CANARIES",
    "SSTI_MAX_REQUESTS",
    "TIME_PAYLOADS",
    "command_injection",
    "ssti",
]
