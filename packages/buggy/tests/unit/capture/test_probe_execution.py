"""The ``ssti`` and ``command_injection`` probes against a fake origin.

The vulnerable template handlers concatenate the request value into a
template and render it with a small engine that really evaluates arithmetic
between its delimiters; the safe ones pass the value as data. The vulnerable
command handlers hand a command line to a small shell interpreter (``sh`` or
``cmd.exe`` rules) that really splits on separators, expands substitutions
and runs ``echo`` / ``sleep`` / ``ping`` against an injected clock; the safe
ones call the program with an argument list. No handler matches on the
probe's payload strings or knows its numbers, except where a test says so.
"""

from __future__ import annotations

import ast
import html
import json
import operator
import re
import time
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

import buggy.capture.gateway as gateway_module
from buggy.capture.gateway import CaptureGateway, Roots
from buggy.capture.mcp_server import CaptureTools
from buggy.capture.probes import REGISTRY, describe, execution, run_probe
from buggy.capture.probes.base import Context
from buggy.capture.probes.execution import (
    CMD_MAX_REQUESTS,
    OUTPUT_PAYLOADS,
    SSTI_CANARIES,
    SSTI_MAX_REQUESTS,
    TIME_PAYLOADS,
)

from .test_gateway import Site

BASE = "https://app.acme.test"
Handler = Callable[[str, dict[str, str], dict[str, str], bytes], tuple[int, object]]
_OPERATORS = {ast.Mult: operator.mul, ast.Add: operator.add, ast.Sub: operator.sub}


def arithmetic(expression: str, names: dict[str, object] | None = None) -> object:
    """Evaluate integers, ``+ - *``, parentheses and the given names; anything else raises."""

    def walk(node: ast.AST) -> object:
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and names and node.id in names:
            return names[node.id]
        if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
            return _OPERATORS[type(node.op)](walk(node.left), walk(node.right))
        raise ValueError(expression)

    return walk(ast.parse(expression.strip(), mode="eval"))


class Engine:
    """A template engine: evaluates what stands between its delimiters, leaves the rest."""

    SYNTAX = {
        "jinja2_twig": r"\{\{(.*?)\}\}",
        "el_freemarker": r"\$\{(.*?)\}",
        "erb_ejs": r"<%=(.*?)%>",
        "ruby_pug": r"#\{(.*?)\}",
        "smarty": r"\{([^{}]*)\}",
    }

    def __init__(self, family: str) -> None:
        self.tag = re.compile(self.SYNTAX[family])

    def render(self, template: str, context: dict[str, object] | None = None) -> str:
        def evaluate(match: re.Match[str]) -> str:
            try:
                return str(arithmetic(match.group(1), context))
            except (ValueError, SyntaxError):
                return match.group(0)

        return self.tag.sub(evaluate, template)


class Clock:
    """The gateway's stopwatch, advanced by the fake origin instead of by waiting."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _nslookup(args: list[str]) -> str:
    """Standard output of a lookup: an answer for a plain host name, nothing otherwise."""
    if len(args) == 1 and re.fullmatch(r"[a-z0-9.-]+", args[0]):
        return f"Name: {args[0]}\nAddress: 192.0.2.7\n"
    return ""


class Shell:
    """Enough of a POSIX shell to run the command line a handler builds.

    ``;`` ``&`` and ``|`` separate commands, ``$((..))`` is arithmetic, ``$(..)``
    and backticks are command substitution. Only standard output is returned.
    """

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.ran: list[str] = []

    def run(self, line: str) -> str:
        line = re.sub(r"\$\(\((.*?)\)\)", lambda m: str(arithmetic(m.group(1))), line)
        line = re.sub(r"\$\(([^()]*)\)", lambda m: self.run(m.group(1)).strip(), line)
        line = re.sub(r"`([^`]*)`", lambda m: self.run(m.group(1)).strip(), line)
        out: list[str] = []
        for sequence in line.split(";"):
            for job in sequence.split("&"):
                stdout = ""
                for stage in job.split("|"):  # only the last stage writes to the caller
                    stdout = self.execute(stage.split())
                out.append(stdout)
        return "".join(out)

    def execute(self, argv: list[str]) -> str:
        if not argv:
            return ""
        self.ran.append(" ".join(argv))
        name, args = argv[0], argv[1:]
        if name == "echo":
            return " ".join(args) + "\n"
        if name == "sleep":
            self.clock.advance(float(args[0]))
            return ""
        if name == "nslookup":
            return _nslookup(args)
        return ""  # "not found" goes to standard error


class CmdExe(Shell):
    """``cmd.exe``: ``&`` and ``|`` separate commands; no ``;``, no ``$(( ))``, no ``sleep``."""

    def run(self, line: str) -> str:
        out: list[str] = []
        for job in line.split("&"):
            stdout = ""
            for stage in job.split("|"):
                stdout = self.execute(stage.split())
            out.append(stdout)
        return "".join(out)

    def execute(self, argv: list[str]) -> str:
        if not argv:
            return ""
        self.ran.append(" ".join(argv))
        name, args = argv[0].lower(), argv[1:]
        if name == "echo":
            return " ".join(args) + "\r\n"
        if name == "set" and args[:1] == ["/a"]:
            return str(arithmetic(" ".join(args[1:])))
        if name == "ping":
            count = int(args[args.index("-n") + 1]) if "-n" in args else 4
            self.clock.advance(count - 1)  # one second between echo requests
            return f"Reply from {args[-1]}: bytes=32\r\n" * count
        if name == "nslookup":
            return _nslookup(args)
        return ""


class _Dispatch(dict):
    """Lets :class:`Site` route by path: every lookup resolves to the app's handler."""

    def __init__(self, app: App) -> None:
        super().__init__()
        self.app = app

    def get(self, key, default=None):
        method, url = key
        return lambda headers, body: self.app.handle(method, url, headers, body)


class App:
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.handlers: dict[str, Handler] = {}
        self.requests = 0

    def handle(self, method: str, url: str, headers: dict[str, str], body: bytes):
        self.requests += 1
        parts = urlsplit(url)
        query = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        handler = self.handlers.get(parts.path)
        if handler is None:
            return 404, b"not found"
        self.clock.advance(0.02)
        return handler(method, query, headers, body)


def _roe(**extra) -> str:
    scope = {"machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]}}
    return json.dumps({**scope, **extra})


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clock = Clock()
    # The gateway times each request with ``time.monotonic``; give it the fake clock.
    monkeypatch.setattr(
        gateway_module,
        "time",
        SimpleNamespace(monotonic=clock.monotonic, time=time.time, sleep=time.sleep),
    )
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        _roe(approvals={"state_changing": "not_required"})
    )
    site = Site()
    app = App(clock)
    site.routes = _Dispatch(app)
    gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
    yield SimpleNamespace(gateway=gateway, site=site, app=app, clock=clock, roots=roots)
    gateway.store.close()


def ssti(env, params: dict) -> dict:
    return run_probe(env.gateway, "acme", "ssti", params)


def command(env, params: dict) -> dict:
    return run_probe(env.gateway, "acme", "command_injection", params)


def check_evidence(env, result: dict) -> None:
    """Every request is evidence, each has a named role, and the probe's bound holds."""
    ids = result["evidence_capture_ids"]
    details = result["details"]
    bound = {"ssti": 8, "command_injection": 11}[result["probe"]]
    assert len(ids) == len(env.site.seen) == details["requests_sent"] <= bound
    assert details["max_requests"] == bound
    assert len(set(ids)) == len(ids)
    assert list(details["captures"].values()) == ids
    assert set(details["payloads"]) == set(details["captures"])
    for capture_id in ids:
        stored = env.gateway.store.get("acme", capture_id)
        assert stored is not None and stored.probe == result["probe"]
    roles = list(details["captures"])
    if ids:
        assert roles[0] == "baseline"
    if len(ids) > 1:
        assert roles[1] == "baseline_repeat"


def sent(env, name: str) -> list[str]:
    """The value of one query parameter in every request the origin received."""
    return [parse_qs(urlsplit(url).query)[name][0] for _m, url, _h, _b in env.site.seen]


def body_of(env, result: dict, role: str) -> str:
    capture = env.gateway.store.get("acme", result["details"]["captures"][role])
    return capture.response_body.decode()


def fixed_numbers(monkeypatch: pytest.MonkeyPatch, a: int, b: int) -> int:
    """Make the probe draw ``a`` and ``b``; returns their product."""
    draws = iter([a, b])
    monkeypatch.setattr(execution, "_four_digits", lambda: next(draws))
    return a * b


# ── template endpoints ───────────────────────────────────────────────


def greeting_injectable(engine: Engine) -> Handler:
    """Builds the template from the request value, then renders it."""

    def handler(_method, query, _headers, _body):
        return 200, {"html": engine.render("<p>Hello " + query.get("name", "") + "!</p>")}

    return handler


def greeting_safe(engine: Engine) -> Handler:
    """A static template; the request value is data."""

    def handler(_method, query, _headers, _body):
        page = engine.render("<p>Hello {{ name }}!</p>", {"name": query.get("name", "")})
        return 200, {"html": page}

    return handler


GREETING = {"url": f"{BASE}/greet?name=World", "parameter": "name"}


class TestSsti:
    def test_jinja_style_evaluation_is_found_and_confirmed_by_the_control(self, env) -> None:
        env.app.handlers["/greet"] = greeting_injectable(Engine("jinja2_twig"))
        result = ssti(env, GREETING)
        assert result["status"] == "completed" and result["vulnerable"] is True, result
        assert result["class"] == "injection" and result["cwe"] == "CWE-1336"
        details = result["details"]
        assert details["engine_family"] == "jinja2_twig" and details["technique"] == "arithmetic"
        assert list(details["captures"]) == [
            "baseline",
            "baseline_repeat",
            "canary_jinja2_twig",
            "canary_control",
        ]
        numbers = details["numbers"]
        a, b, product = numbers["a"], numbers["b"], numbers["product"]
        assert 1000 <= a <= 9999 and 1000 <= b <= 9999 and product == a * b
        assert numbers["control"] != product
        assert len(str(numbers["control"])) == len(str(product))
        assert sent(env, "name") == [
            "World",
            "World",
            f"World{{{{{a}*{b}}}}}",
            f"World{numbers['control']}",
        ]
        # The engine did the multiplication; the control page carries only what was sent.
        assert f"Hello World{product}!" in body_of(env, result, "canary_jinja2_twig")
        assert f"Hello World{numbers['control']}!" in body_of(env, result, "canary_control")
        (canary,) = details["canaries"]
        assert canary["outcome"] == "evaluated" and canary["payload_reflected"] is False
        assert "static" in result["remediation"]
        check_evidence(env, result)

    def test_el_style_evaluation_is_found_by_the_second_canary(self, env) -> None:
        env.app.handlers["/greet"] = greeting_injectable(Engine("el_freemarker"))
        result = ssti(env, GREETING)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["engine_family"] == "el_freemarker"
        a, b = details["numbers"]["a"], details["numbers"]["b"]
        assert details["payloads"]["canary_el_freemarker"] == f"World${{{a}*{b}}}"
        # The first canary is not this engine's syntax: it came back as text.
        first, second = details["canaries"]
        assert first["name"] == "jinja2_twig" and first["outcome"] == "reflected_as_text"
        assert second["outcome"] == "evaluated"
        assert details["requests_sent"] == 5
        check_evidence(env, result)

    @pytest.mark.parametrize("family", [name for name, _payload in SSTI_CANARIES])
    def test_each_engine_family_is_named(self, env, family: str) -> None:
        env.app.handlers["/greet"] = greeting_injectable(Engine(family))
        result = ssti(env, GREETING)
        assert result["vulnerable"] is True, result
        assert result["details"]["engine_family"] == family
        assert family in result["summary"]
        check_evidence(env, result)

    def test_single_brace_engine_is_not_reported_as_double_brace(self, env) -> None:
        # It evaluates the inside of the first canary and leaves the outer braces.
        env.app.handlers["/greet"] = greeting_injectable(Engine("smarty"))
        result = ssti(env, GREETING)
        product = result["details"]["numbers"]["product"]
        assert "{" + str(product) + "}" in body_of(env, result, "canary_jinja2_twig")
        assert result["details"]["engine_family"] == "smarty"

    def test_value_passed_as_data_is_not_flagged(self, env) -> None:
        env.app.handlers["/greet"] = greeting_safe(Engine("jinja2_twig"))
        result = ssti(env, GREETING)
        assert result["status"] == "completed" and result["vulnerable"] is False, result
        details = result["details"]
        assert details["engine_family"] is None and details["technique"] is None
        # All five canaries were sent and came back as the text that was sent; no control.
        assert [c["name"] for c in details["canaries"]] == [name for name, _p in SSTI_CANARIES]
        assert {c["outcome"] for c in details["canaries"]} == {"reflected_as_text"}
        assert details["requests_sent"] == 7 and "canary_control" not in details["captures"]
        a, b = details["numbers"]["a"], details["numbers"]["b"]
        assert f"Hello World{{{{{a}*{b}}}}}!" in body_of(env, result, "canary_jinja2_twig")
        check_evidence(env, result)

    def test_payload_reflected_verbatim_and_entity_encoded_is_not_flagged(self, env) -> None:
        def handler(_method, query, _headers, _body):
            return 200, f"<p>You searched for {html.escape(query.get('name', ''))}</p>".encode()

        env.app.handlers["/greet"] = handler
        result = ssti(env, GREETING)
        assert result["vulnerable"] is False, result
        assert all(c["payload_reflected"] for c in result["details"]["canaries"])
        check_evidence(env, result)

    def test_value_that_is_not_reflected_is_not_flagged(self, env) -> None:
        env.app.handlers["/greet"] = lambda *_args: (200, {"html": "<p>Hello!</p>"})
        result = ssti(env, GREETING)
        assert result["vulnerable"] is False, result
        assert {c["outcome"] for c in result["details"]["canaries"]} == {"not_evaluated"}
        check_evidence(env, result)

    @pytest.mark.parametrize("everywhere", [False, True], ids=["error-page", "every-page"])
    def test_control_stops_a_page_that_carries_the_product_by_chance(
        self, env, monkeypatch, everywhere: bool
    ) -> None:
        # Nothing is evaluated or reflected here. The page prints a fixed number
        # that happens to be the product of the run's two integers: on every
        # response, or only on the "unknown customer" page (so not on the baseline).
        product = fixed_numbers(monkeypatch, 4673, 8291)

        def handler(_method, query, _headers, _body):
            if query.get("name") == "World" and not everywhere:
                return 200, b"<p>Hello World!</p>"
            return 200, f"<p>Unknown customer. Quote incident {product}.</p>".encode()

        env.app.handlers["/greet"] = handler
        result = ssti(env, GREETING)
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        details = result["details"]
        assert details["engine_family"] is None and details["technique"] is None
        assert list(details["captures"])[2:] == ["canary_jinja2_twig", "canary_control"]
        (canary,) = details["canaries"]
        # Without the control this response would have counted: product there, payload not.
        assert canary["product_present"] is True and canary["payload_reflected"] is False
        assert canary["outcome"] == "coincidence"
        assert str(product) in body_of(env, result, "canary_control")
        assert "part of the page" in result["summary"]
        check_evidence(env, result)

    def test_same_numbers_on_an_injectable_page_are_still_found(self, env, monkeypatch) -> None:
        # The counterpart of the test above: fixing the numbers does not blind the probe.
        product = fixed_numbers(monkeypatch, 4673, 8291)
        env.app.handlers["/greet"] = greeting_injectable(Engine("jinja2_twig"))
        result = ssti(env, GREETING)
        assert result["vulnerable"] is True and result["details"]["numbers"]["product"] == product

    def test_product_next_to_the_expression_text_is_not_proof(self, env) -> None:
        # Evaluates the value AND prints what was typed, with every special
        # character as a numeric entity. The rule asks for the product without
        # the expression text, so no canary counts and the verdict is "cannot tell".
        engine = Engine("jinja2_twig")

        def handler(_method, query, _headers, _body):
            name = query.get("name", "")
            typed = "".join(c if c.isalnum() else f"&#{ord(c)};" for c in name)
            return 200, f"<p>{engine.render(name)}</p><input value='{typed}'>".encode()

        env.app.handlers["/greet"] = handler
        result = ssti(env, GREETING)
        assert result["vulnerable"] is None, result
        first = result["details"]["canaries"][0]
        assert first["product_present"] and first["payload_reflected"]
        assert first["outcome"] == "ambiguous"
        assert "canary_control" not in result["details"]["captures"]
        assert "does not count as proof" in result["summary"]
        check_evidence(env, result)

    def _profile(self, engine: Engine, *, form: bool) -> Handler:
        def handler(method, _query, headers, body):
            assert method == "POST"
            if form:
                assert headers["content-type"] == "application/x-www-form-urlencoded"
                fields = {k: v[0] for k, v in parse_qs(body.decode()).items()}
                bio, plan = fields["bio"], fields["plan"]
            else:
                assert headers["content-type"] == "application/json"
                document = json.loads(body)
                bio, plan = document["profile"]["bio"], document["plan"]
            assert plan == "free"  # the other field arrives unchanged in every request
            return 200, {"preview": engine.render("<div>" + bio + "</div>")}

        return handler

    @pytest.mark.parametrize("form", [False, True], ids=["json", "form"])
    def test_body_parameters(self, env, form: bool) -> None:
        env.app.handlers["/profile"] = self._profile(Engine("erb_ejs"), form=form)
        params = {"url": f"{BASE}/profile", "method": "POST"}
        if form:
            params |= {"location": "form", "parameter": "bio", "body": "bio=hi&plan=free"}
        else:
            body = {"profile": {"bio": "hi"}, "plan": "free"}
            params |= {"location": "json", "parameter": "profile.bio", "body": body}
        result = ssti(env, params)
        assert result["vulnerable"] is True, result
        assert result["details"]["engine_family"] == "erb_ejs"
        assert result["details"]["location"] == ("form" if form else "json")
        check_evidence(env, result)

    def test_numbers_change_from_run_to_run(self, env) -> None:
        env.app.handlers["/greet"] = greeting_safe(Engine("jinja2_twig"))
        products = {ssti(env, GREETING)["details"]["numbers"]["product"] for _ in range(4)}
        assert len(products) > 1


# ── command endpoints ────────────────────────────────────────────────

LOOKUP = {"url": f"{BASE}/lookup?host=example.org", "parameter": "host"}


def lookup_injectable(shell: Shell, *, show_output: bool = True, strip: str = "") -> Handler:
    """Builds a command line from the request value and gives it to a shell."""

    def handler(_method, query, _headers, _body):
        host = query.get("host", "")
        for character in strip:
            host = host.replace(character, "")
        output = shell.run(f"nslookup {host}")
        return 200, {"output": output} if show_output else {"queued": True}

    return handler


def lookup_safe(shell: Shell, *, show_output: bool = True) -> Handler:
    """Runs the same program with an argument list: no shell reads the value."""

    def handler(_method, query, _headers, _body):
        output = shell.execute(["nslookup", query.get("host", "")])
        return 200, {"output": output} if show_output else {"queued": True}

    return handler


class TestCommandOutput:
    def test_a_page_with_a_changing_timing_figure_does_not_stop_the_probe(self, env) -> None:
        # A ping page prints different round-trip times on every request.
        shell = Shell(env.clock)
        inner = lookup_injectable(shell)

        def handler(method, query, headers, body):
            status, document = inner(method, query, headers, body)
            jitter = f"64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.0{env.app.requests} ms"
            return status, {**document, "ping": jitter}

        env.app.handlers["/lookup"] = handler
        result = command(env, LOOKUP)
        assert result["vulnerable"] is True, result
        assert result["details"]["baseline"]["volatile"] is True

    def test_shell_that_prints_its_output_is_found_by_the_arithmetic_echo(self, env) -> None:
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell)
        result = command(env, LOOKUP)
        assert result["status"] == "completed" and result["vulnerable"] is True, result
        assert result["class"] == "injection" and result["cwe"] == "CWE-78"
        details = result["details"]
        assert details["technique"] == "output" and details["separator"] == "semicolon"
        assert list(details["captures"]) == [
            "baseline",
            "baseline_repeat",
            "output_semicolon",
            "output_control",
        ]
        numbers = details["numbers"]
        a, b, product = numbers["a"], numbers["b"], numbers["product"]
        assert product == a * b and 1000 <= a <= 9999 and 1000 <= b <= 9999
        assert sent(env, "host") == [
            "example.org",
            "example.org",
            f"example.org;echo $(({a}*{b}))",
            f"example.org{numbers['control']}",
        ]
        # The shell ran a second command, and all it did was print a number.
        assert shell.ran[2:4] == ["nslookup example.org", f"echo {product}"]
        assert json.loads(body_of(env, result, "output_semicolon"))["output"].endswith(
            f"{product}\n"
        )
        assert str(product) not in body_of(env, result, "output_control")
        assert "time" not in details  # found by output: no delay payload was sent
        assert "argument list" in result["remediation"]
        check_evidence(env, result)

    @pytest.mark.parametrize(
        ("strip", "separator"),
        [(";", "pipe"), (";|", "backtick"), (";|`", "subshell")],
    )
    def test_next_separator_is_found_when_a_filter_removes_the_earlier_ones(
        self, env, strip: str, separator: str
    ) -> None:
        # nslookup prints an answer for a plain name only, so a substitution shows
        # up when the substituted number becomes part of the name it echoes.
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell, strip=strip)
        result = command(env, LOOKUP)
        assert result["vulnerable"] is True, result
        assert result["details"]["separator"] == separator
        assert [t["outcome"] for t in result["details"]["output"]][-1] == "evaluated"
        check_evidence(env, result)

    def test_cmd_exe_is_found_by_set_a(self, env) -> None:
        shell = CmdExe(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell)
        result = command(env, LOOKUP)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "output" and details["separator"] == "windows_ampersand"
        numbers = details["numbers"]
        assert details["payloads"]["output_windows_ampersand"] == (
            f"example.org& set /a {numbers['a']}*{numbers['b']}"
        )
        # cmd.exe echoed "$((a*b))" for the pipe payload instead of computing it.
        outcomes = {t["name"]: t["outcome"] for t in details["output"]}
        assert outcomes["pipe"] == "reflected_as_text"
        assert outcomes["windows_ampersand"] == "evaluated"
        assert details["requests_sent"] == 8
        check_evidence(env, result)

    def test_program_called_with_an_argument_list_is_not_flagged(self, env) -> None:
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_safe(shell)
        result = command(env, LOOKUP)
        assert result["status"] == "completed" and result["vulnerable"] is False, result
        details = result["details"]
        assert details["technique"] is None and "separator" not in details
        assert [t["name"] for t in details["output"]] == [name for name, _p in OUTPUT_PAYLOADS]
        assert {t["outcome"] for t in details["output"]} == {"not_evaluated"}
        assert [t["name"] for t in details["time"]["tried"]] == [n for n, _w, _z in TIME_PAYLOADS]
        assert all(t["delay_extra_ms"] < 2500 for t in details["time"]["tried"])
        assert details["requests_sent"] == 10  # 2 + 5 + 3, and no control was needed
        # Only the lookup program ever ran, once per request, with the value as one argument.
        assert len(shell.ran) == 10 and all(line.startswith("nslookup ") for line in shell.ran)
        check_evidence(env, result)

    def test_payload_reflected_verbatim_is_not_flagged(self, env) -> None:
        def handler(_method, query, _headers, _body):
            return 200, {"error": f"cannot resolve {query.get('host', '')}: unknown host"}

        env.app.handlers["/lookup"] = handler
        result = command(env, LOOKUP)
        assert result["vulnerable"] is False, result
        assert {t["outcome"] for t in result["details"]["output"]} == {"reflected_as_text"}
        numbers = result["details"]["numbers"]
        assert f"$(({numbers['a']}*{numbers['b']}))" in body_of(env, result, "output_semicolon")
        check_evidence(env, result)

    def test_control_stops_a_page_that_carries_the_product_by_chance(
        self, env, monkeypatch
    ) -> None:
        # No shell anywhere: a name that does not resolve gets a fixed support
        # reference, which happens to be the product of the run's two integers.
        product = fixed_numbers(monkeypatch, 3187, 6449)

        def handler(_method, query, _headers, _body):
            if query.get("host") == "example.org":
                return 200, {"output": "Name: example.org\nAddress: 192.0.2.7\n"}
            return 200, {"output": "", "note": f"lookup failed, reference {product}"}

        env.app.handlers["/lookup"] = handler
        result = command(env, LOOKUP)
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        details = result["details"]
        assert details["technique"] is None
        assert list(details["captures"])[2:] == ["output_semicolon", "output_control"]
        (tried,) = details["output"]
        assert tried["product_present"] is True and tried["payload_reflected"] is False
        assert tried["outcome"] == "coincidence"
        assert "time" not in details  # the run stops: no further payload is sent
        check_evidence(env, result)

    def test_command_line_echoed_next_to_its_output_is_settled_by_time(self, env) -> None:
        # The page prints the command line it ran and then its output, so the
        # product never appears without the payload text: output alone cannot
        # prove it, and the delay does.
        shell = Shell(env.clock)

        def handler(_method, query, _headers, _body):
            line = f"nslookup {query.get('host', '')}"
            return 200, {"console": f"$ {line}\n{shell.run(line)}"}

        env.app.handlers["/lookup"] = handler
        result = command(env, LOOKUP)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "time" and details["separator"] == "semicolon"
        assert details["output"][0]["outcome"] == "ambiguous"
        check_evidence(env, result)
        # Without the delay payloads the same endpoint is "cannot tell", not a pass.
        env.site.seen.clear()
        result = command(env, {**LOOKUP, "allow_time": False})
        assert result["vulnerable"] is None, result
        assert "does not count as proof" in result["summary"]


class TestCommandTime:
    def test_blind_shell_is_found_by_delay_with_a_no_wait_control(self, env) -> None:
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell, show_output=False)
        result = command(env, LOOKUP)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "time" and details["separator"] == "semicolon"
        assert details["allow_time"] is True  # the default
        assert list(details["captures"])[-2:] == ["time_semicolon", "time_control_semicolon"]
        assert details["payloads"]["time_semicolon"] == "example.org;sleep 3"
        assert details["payloads"]["time_control_semicolon"] == "example.org;sleep 0"
        (tried,) = details["time"]["tried"]
        assert tried["delay_extra_ms"] >= 2500 and tried["control_extra_ms"] <= 1000
        # The five output payloads really were negative first.
        assert {t["outcome"] for t in details["output"]} == {"not_evaluated"}
        assert details["requests_sent"] == 9
        check_evidence(env, result)
        delayed = env.gateway.store.get("acme", details["captures"]["time_semicolon"])
        assert delayed.elapsed_ms >= 3000
        assert "sleep 3" in shell.ran and "sleep 0" in shell.ran

    def test_pipe_delay_is_found_when_the_semicolon_is_filtered(self, env) -> None:
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell, show_output=False, strip=";")
        result = command(env, LOOKUP)
        assert result["vulnerable"] is True, result
        assert result["details"]["separator"] == "pipe"
        assert [t["name"] for t in result["details"]["time"]["tried"]] == ["semicolon", "pipe"]
        check_evidence(env, result)

    def test_blind_cmd_exe_is_found_by_ping_and_fits_the_request_bound(self, env) -> None:
        shell = CmdExe(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell, show_output=False)
        result = command(env, LOOKUP)
        assert result["vulnerable"] is True, result
        details = result["details"]
        assert details["technique"] == "time" and details["separator"] == "windows_ampersand"
        assert details["payloads"]["time_windows_ampersand"].endswith("& ping -n 4 -w 3 127.0.0.1")
        assert details["payloads"]["time_control_windows_ampersand"].endswith(
            "& ping -n 1 -w 3 127.0.0.1"
        )
        assert details["requests_sent"] == 11 == CMD_MAX_REQUESTS  # the longest possible run
        check_evidence(env, result)

    def test_delay_payloads_are_not_sent_when_switched_off(self, env) -> None:
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell, show_output=False)
        for off in (False, "false"):
            env.site.seen.clear()
            result = command(env, {**LOOKUP, "allow_time": off})
            assert result["vulnerable"] is False, result
            assert result["details"]["allow_time"] is False and "time" not in result["details"]
            assert result["details"]["requests_sent"] == 7
            assert not any("sleep" in value or "ping" in value for value in sent(env, "host"))
            check_evidence(env, result)
        assert not any(line.startswith("sleep") for line in shell.ran)

    def test_blind_argument_list_endpoint_never_delays(self, env) -> None:
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_safe(shell, show_output=False)
        result = command(env, LOOKUP)
        assert result["vulnerable"] is False, result
        assert all("control_extra_ms" not in t for t in result["details"]["time"]["tried"])
        assert result["details"]["requests_sent"] == 10
        check_evidence(env, result)

    def test_slow_control_means_cannot_tell(self, env) -> None:
        # Slow for any value that is not a plain host name: the wait is not caused by sleep.
        def handler(_method, query, _headers, _body):
            if not re.fullmatch(r"[a-z0-9.]+", query.get("host", "")):
                env.clock.advance(4.0)
            return 200, {"queued": True}

        env.app.handlers["/lookup"] = handler
        # The slow answers would also slow the output payloads; that is not a signal.
        result = command(env, LOOKUP)
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert result["details"]["technique"] is None
        (tried,) = result["details"]["time"]["tried"]
        assert tried["delay_extra_ms"] >= 2500 and tried["control_extra_ms"] > 1000
        assert "timing is unreliable" in result["summary"]
        check_evidence(env, result)

    def test_a_delay_below_the_threshold_is_not_a_finding(self, env) -> None:
        def handler(_method, query, _headers, _body):
            if "sleep" in query.get("host", ""):  # stands in for a slow validation path
                env.clock.advance(2.0)
            return 200, {"queued": True}

        env.app.handlers["/lookup"] = handler
        result = command(env, LOOKUP)
        assert result["vulnerable"] is False, result
        assert all("control_extra_ms" not in t for t in result["details"]["time"]["tried"])
        check_evidence(env, result)

    def test_slow_baseline_is_not_mistaken_for_a_delay(self, env) -> None:
        # Every request takes 3 s; the delay must be measured on top of that.
        def handler(_method, _query, _headers, _body):
            env.clock.advance(3.0)
            return 200, {"queued": True}

        env.app.handlers["/lookup"] = handler
        result = command(env, LOOKUP)
        assert result["vulnerable"] is False, result
        assert result["details"]["time"]["baseline_ms"] >= 3000
        check_evidence(env, result)


# ── cannot tell ──────────────────────────────────────────────────────

PROBES = pytest.mark.parametrize(
    ("run", "params"), [(ssti, GREETING), (command, LOOKUP)], ids=["ssti", "command_injection"]
)


class TestCannotTell:
    @PROBES
    def test_unstable_page(self, env, run, params: dict) -> None:
        def handler(_method, _query, _headers, _body):
            return 200, (chr(ord("A") + env.app.requests) * 300).encode()

        env.app.handlers[urlsplit(params["url"]).path] = handler
        result = run(env, params)
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert "unstable" in result["summary"]
        assert list(result["details"]["captures"]) == ["baseline", "baseline_repeat"]
        check_evidence(env, result)

    @PROBES
    def test_unstable_status(self, env, run, params: dict) -> None:
        def handler(_method, _query, _headers, _body):
            return (200 if env.app.requests % 2 else 429), b"same body"

        env.app.handlers[urlsplit(params["url"]).path] = handler
        result = run(env, params)
        assert result["vulnerable"] is None and len(env.site.seen) == 2

    @PROBES
    @pytest.mark.parametrize("failure", ["server_error", "transport"])
    def test_failed_baseline(self, env, run, params: dict, failure: str) -> None:
        def handler(_method, _query, _headers, _body):
            if failure == "transport":
                raise ConnectionResetError("connection reset by peer")
            return 503, b"maintenance"

        env.app.handlers[urlsplit(params["url"]).path] = handler
        result = run(env, params)
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert "baseline request failed" in result["summary"]
        assert len(env.site.seen) == 1  # nothing is injected into a broken endpoint
        check_evidence(env, result)

    @PROBES
    def test_out_of_scope_target_is_refused_and_nothing_is_sent(
        self, env, run, params: dict
    ) -> None:
        url = params["url"].replace("app.acme.test", "other.test")
        result = run(env, {**params, "url": url})
        assert result["status"] == "completed" and result["vulnerable"] is None, result
        assert result["details"]["refusal"]["code"] == "OUT_OF_SCOPE"
        assert result["evidence_capture_ids"] == [] and env.site.seen == []

    @PROBES
    def test_state_changing_method_waits_for_approval(self, env, run, params: dict) -> None:
        (env.roots.control / "acme" / "roe.json").write_text(_roe())
        parameter = params["parameter"]
        post = {
            "url": params["url"].partition("?")[0],
            "method": "POST",
            "location": "json",
            "parameter": parameter,
            "body": {parameter: "x"},
        }
        result = run(env, post)
        # The run is held as a whole: one approval request, and no request sent.
        assert result["status"] == "refused" and "vulnerable" not in result, result
        assert result["code"] == "APPROVAL_REQUIRED" and result["request_id"].startswith("apr-")
        assert env.site.seen == []

    @PROBES
    def test_request_bound_is_enforced_by_the_sender(
        self, env, monkeypatch, run, params: dict
    ) -> None:
        env.app.handlers[urlsplit(params["url"]).path] = lambda *_args: (200, {"ok": True})
        monkeypatch.setattr(execution, "SSTI_MAX_REQUESTS", 3)
        monkeypatch.setattr(execution, "CMD_MAX_REQUESTS", 3)
        result = run(env, params)
        assert result["vulnerable"] is None, result
        assert "request bound (3)" in result["summary"] and len(env.site.seen) == 3

    @PROBES
    def test_payload_request_without_an_answer(self, env, run, params: dict) -> None:
        parameter = params["parameter"]

        def handler(_method, query, _headers, _body):
            if re.search(r"\d{4}\*\d{4}", query.get(parameter, "")):
                raise TimeoutError("timed out")
            return 200, {"ok": True}

        env.app.handlers[urlsplit(params["url"]).path] = handler
        result = run(env, {**params, "allow_time": False})
        assert result["vulnerable"] is None, result
        assert "got no answer" in result["summary"]
        check_evidence(env, result)


class TestApprovalHold:
    """A shell payload is state-changing whatever the method; the gateway only holds by method."""

    def test_shell_payloads_are_not_sent_over_get_while_approval_is_required(self, env) -> None:
        (env.roots.control / "acme" / "roe.json").write_text(_roe())
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell)
        result = command(env, LOOKUP)
        assert result["status"] == "refused" and result["code"] == "APPROVAL_REQUIRED", result
        assert result["request_id"].startswith("apr-")
        # Nothing left the gateway, not even the baseline; the shell saw nothing.
        assert env.site.seen == [] and shell.ran == []

    def test_probe_called_without_an_approved_run_holds_its_payloads(self, env) -> None:
        # Defence in depth: the probe itself refuses when it is reached without a grant.
        (env.roots.control / "acme" / "roe.json").write_text(_roe())
        shell = Shell(env.clock)
        env.app.handlers["/lookup"] = lookup_injectable(shell)
        result = execution.command_injection(
            Context(env.gateway, "acme", "command_injection"), LOOKUP
        ).to_dict()
        assert result["vulnerable"] is None, result
        refusal = result["details"]["refusal"]
        assert refusal["code"] == "APPROVAL_REQUIRED" and refusal["held_by"] == "probe"
        assert sent(env, "host") == ["example.org", "example.org"]
        assert shell.ran == ["nslookup example.org"] * 2

    def test_same_request_runs_once_the_scope_waives_approval(self, env) -> None:
        env.app.handlers["/lookup"] = lookup_injectable(Shell(env.clock))
        assert command(env, LOOKUP)["vulnerable"] is True

    def test_template_canaries_are_not_held(self, env) -> None:
        # Evaluating a multiplication changes nothing: ssti is not state-changing.
        (env.roots.control / "acme" / "roe.json").write_text(_roe())
        env.app.handlers["/greet"] = greeting_injectable(Engine("jinja2_twig"))
        assert ssti(env, GREETING)["vulnerable"] is True


# ── inputs, registry, payload hygiene ────────────────────────────────


class TestContract:
    def test_registered_and_described(self) -> None:
        template, shell = REGISTRY["ssti"], REGISTRY["command_injection"]
        assert (template.vuln_class, template.cwe) == ("injection", "CWE-1336")
        assert (shell.vuln_class, shell.cwe) == ("injection", "CWE-78")
        assert template.state_changing is False and shell.state_changing is True
        assert template.run is execution.ssti and shell.run is execution.command_injection
        # Appended after the eight earlier probes, whose order is untouched.
        names = list(REGISTRY)
        assert names[:8] == [
            "jwt_alg_none", "idor", "ssrf_canary", "numeric_boundary", "mass_assignment",
            "graphql_checks", "sqli", "xss_reflected",
        ]  # fmt: skip
        assert names[8:10] == ["ssti", "command_injection"]
        described = {d["probe"]: d for d in describe()}
        common = {"url", "method", "parameter", "location", "value", "body", "headers"}
        assert set(described["ssti"]["params"]) == common
        assert set(described["command_injection"]["params"]) == common | {"allow_time"}
        assert described["command_injection"]["state_changing"] is True

    def test_probe_list_and_probe_run_tools_expose_them(self, env) -> None:
        tools = CaptureTools(env.gateway, engagement="acme")
        listed = {p["probe"]: p for p in tools.probe_list()["probes"]}
        assert listed["ssti"]["cwe"] == "CWE-1336"
        assert listed["command_injection"]["cwe"] == "CWE-78"
        env.app.handlers["/greet"] = greeting_injectable(Engine("jinja2_twig"))
        env.app.handlers["/lookup"] = lookup_injectable(Shell(env.clock))
        found = tools.probe_run("acme", "ssti", json.dumps(GREETING))
        assert found["vulnerable"] is True and found["details"]["engine_family"] == "jinja2_twig"
        json.dumps(found)  # the whole result is JSON-serialisable
        found = tools.probe_run("acme", "command_injection", json.dumps(LOOKUP))
        assert found["vulnerable"] is True and found["details"]["technique"] == "output"
        json.dumps(found)

    @pytest.mark.parametrize("name", ["ssti", "command_injection"])
    @pytest.mark.parametrize(
        "params",
        [
            {"url": f"{BASE}/lookup"},  # no parameter
            {"parameter": "host"},  # no url
            {"url": f"{BASE}/lookup", "parameter": "host"},  # no baseline value anywhere
            {"url": f"{BASE}/lookup?host=a", "parameter": "host", "location": "cookie"},
            {"url": f"{BASE}/lookup", "parameter": "host", "location": "json", "body": "[1]"},
            {"url": f"{BASE}/lookup", "parameter": "host", "location": "form", "body": ["host"]},
        ],
    )
    def test_bad_input_is_an_error_and_sends_nothing(self, env, name: str, params: dict) -> None:
        result = run_probe(env.gateway, "acme", name, params)
        assert result["status"] == "error", result
        assert env.site.seen == []

    @PROBES
    def test_other_query_parameters_and_headers_are_preserved(self, env, run, params: dict) -> None:
        path = urlsplit(params["url"]).path
        env.app.handlers[path] = lambda *_args: (200, {"ok": True})
        url = params["url"].replace("?", "?page=2&") + "&sort=name"
        run(env, {**params, "url": url, "headers": {"Authorization": "Bearer t0ken"}})
        assert len(env.site.seen) >= 7
        for _method, seen_url, headers, _body in env.site.seen:
            query = parse_qs(urlsplit(seen_url).query)
            assert query["page"] == ["2"] and query["sort"] == ["name"]
            assert headers["authorization"] == "Bearer t0ken"

    def test_bounds_cover_the_longest_run(self) -> None:
        assert (len(SSTI_CANARIES), len(OUTPUT_PAYLOADS), len(TIME_PAYLOADS)) == (5, 5, 3)
        assert SSTI_MAX_REQUESTS == 2 + len(SSTI_CANARIES) + 1 == 8
        # An output control ends the run, so only the delay control adds to the payloads.
        assert CMD_MAX_REQUESTS == 2 + len(OUTPUT_PAYLOADS) + len(TIME_PAYLOADS) + 1 == 11

    def test_template_canaries_are_one_multiplication_each(self) -> None:
        assert [payload for _name, payload in SSTI_CANARIES] == [
            "{{a*b}}",
            "${a*b}",
            "<%= a*b %>",
            "#{a*b}",
            "{a*b}",
        ]

    def test_shell_payloads_only_echo_sleep_or_ping_localhost(self) -> None:
        payloads = [payload for _name, payload in OUTPUT_PAYLOADS]
        payloads += [p for _name, wait, no_wait in TIME_PAYLOADS for p in (wait, no_wait)]
        for payload in payloads:
            # What is left once the separators and substitution marks are gone is
            # one command, and it is one of four harmless ones.
            words = re.sub(r"[;|&`]|\$\(\(|\)\)|\$\(|\)", " ", payload).split()
            assert words[0] in {"echo", "sleep", "set", "ping"}, payload
            assert not re.search(r"[<>]|/etc|/dev|\.\.", payload), payload  # no files, no redirects
            if words[0] == "echo":
                assert words[1:] == ["a*b"], payload
            elif words[0] == "set":
                assert words[1:] == ["/a", "a*b"], payload
            elif words[0] == "sleep":
                assert words[1:] in (["3"], ["0"]), payload
            else:
                assert words[1:] in (
                    ["-n", "4", "-w", "3", "127.0.0.1"],
                    ["-n", "1", "-w", "3", "127.0.0.1"],
                ), payload
