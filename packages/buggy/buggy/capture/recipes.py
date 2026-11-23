"""Checks the agent builds itself: a recipe is data that Buggy's code runs through the gateway.

When no probe fits a lead, the agent describes a multi-step check as JSON:
which requests to send (as which declared test account), what to take from
each response for the next one, and how to decide. This module validates that
description and runs it. Nothing the agent writes is ever executed: a recipe
has no expressions, loops or conditionals, only literal requests with
``{{var}}`` placeholders, fixed extraction rules and fixed comparisons. Every
request goes through :meth:`CaptureGateway.send`, so scope, the internal-address
block, the approval hold, the rate limit and the ledger apply to each of them.

A recipe::

    {"name": "order-read-by-other", "class": "access_control",
     "title": "...", "endpoint": "https://shop.test/api/orders",
     "remediation": "Check that the order belongs to the caller before returning it.",
     "steps": [
        {"id": "create", "method": "POST", "url": "https://shop.test/api/orders",
         "identity": "alice", "body": {"item": "book-{{rand}}"},
         "expect": {"status": [200, 201]},
         "extract": {"order": {"from": "json", "path": "id"}}},
        {"id": "owner", "method": "GET", "url": "https://shop.test/api/orders/{{order}}",
         "identity": "alice"},
        {"id": "other", "method": "GET", "url": "https://shop.test/api/orders/{{order}}",
         "identity": "bob"},
        {"id": "nobody", "method": "GET", "url": "https://shop.test/api/orders/{{order}}",
         "identity": ""}],
     "verdict": {
        "vulnerable_if": [{"step": "other", "status": 200}, {"step": "other", "same_as": "owner"}],
        "control": [{"step": "owner", "status": 200}, {"step": "nobody", "status": [401, 403]}]}}

The run is ``vulnerable: true`` only when every ``vulnerable_if`` condition
and every ``control`` condition holds; ``false`` when the controls hold and a
``vulnerable_if`` condition does not; ``null`` when a control fails, a step's
``expect`` fails (``precondition_failed``) or a step got no response.
Extracted values are never returned, only the names of the variables.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import string
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from buggy.capture.gateway import SAFE_METHODS, CaptureGateway, GatewayRefusal, ProbeGrant
from buggy.capture.probes.base import similarity, text
from buggy.capture.store import Capture
from buggy.findings.model import CLASSES
from buggy.findings.verifier import DIFFERS_BELOW, SAME_AS_MIN

METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
MAX_STEPS = 12
MAX_CONDITIONS = 20
MAX_BODY = 64 * 1024
MAX_URL = 2048
MAX_TITLE = 300
MAX_TEXT = 4000
MAX_SHORT = 500
MAX_HEADERS = 30
MAX_HEADER_VALUE = 4096
MAX_EXTRACT = 10
MAX_EXPECT_STRINGS = 20
MAX_PATTERN = 200
MAX_PATH = 200
MIN_REMEDIATION = 30
#: How much of a response body an extraction regex or a comparison looks at.
SCAN_LIMIT = 256 * 1024
MAX_VALUE = 4096
#: Requests one approved run may send beyond its step count (a session renewed after a 401).
RUN_MARGIN = 2

SLUG = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
IDENTITY = re.compile(r"^[A-Za-z0-9_.@:-]{1,64}$")
#: A group with a repeat inside that is itself repeated, e.g. ``(a+)+`` or ``(.*x)*``.
#: Such a pattern can backtrack for a very long time, and a running match cannot
#: be interrupted, so it is refused when the recipe is checked.
_NESTED_REPEAT = re.compile(r"\([^()]*[+*][^()]*\)\s*(?:[+*]|\{\d*,\d*\})")
PLACEHOLDER = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
_AUTHORITY = re.compile(r"^(https?)://([^/?#]*)", re.IGNORECASE)

BUILTINS = ("rand", "ts")
PIPES: dict[str, Callable[[str], str]] = {
    "urlencode": lambda v: urllib.parse.quote(v, safe=""),
    "b64": lambda v: base64.b64encode(v.encode()).decode("ascii"),
    "b64url": lambda v: base64.urlsafe_b64encode(v.encode()).rstrip(b"=").decode("ascii"),
    "json": lambda v: json.dumps(v)[1:-1],
    "lower": str.lower,
    "upper": str.upper,
}
EXTRACT_FROM = {"json": "path", "header": "name", "regex": "pattern", "status": ""}
CONDITION_KINDS = (
    "status",
    "body_contains",
    "body_not_contains",
    "same_as",
    "differs_from",
    "json",
)
COMPARATORS = ("equals", "gt", "lt")

RECIPE_KEYS = frozenset(
    {
        "name",
        "class",
        "title",
        "endpoint",
        "parameter",
        "remediation",
        "steps",
        "verdict",
        "state_changing",
        # The rule the check tests ("a user can read only their own order"); optional.
        "invariant",
    }
)
STEP_KEYS = frozenset({"id", "method", "url", "headers", "body", "identity", "extract", "expect"})
EXPECT_KEYS = frozenset({"status", "body_contains", "body_not_contains"})

CONTROL_REQUIRED = (
    "a recipe needs at least one control condition: a control is the step that shows the "
    "normal, expected behaviour (the owner can read their own order, a request without "
    "credentials is refused), so that a positive result means more than 'the page answered'"
)

VULNERABLE = "vulnerable"
NOT_VULNERABLE = "not_vulnerable"
PRECONDITION_FAILED = "precondition_failed"
CONTROL_FAILED = "control_failed"
NOT_SENT = "not_sent"


class RecipeError(ValueError):
    """A recipe is malformed. ``path`` names the exact place (``steps[1].extract.id.path``)."""

    def __init__(self, path: str, message: str) -> None:
        super().__init__(f"{path}: {message}")
        self.path = path
        self.message = message

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class Step:
    id: str
    method: str
    url: str
    headers: dict[str, str]
    body: Any
    identity: str
    extract: dict[str, dict[str, str]]
    expect: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Recipe:
    """A validated recipe. ``data`` is its normalised JSON; ``canonical`` the approved form."""

    name: str
    vuln_class: str
    title: str
    endpoint: str
    parameter: str
    remediation: str
    steps: tuple[Step, ...]
    vulnerable_if: tuple[dict[str, Any], ...]
    control: tuple[dict[str, Any], ...]
    declared_state_changing: bool
    data: dict[str, Any]

    @property
    def canonical(self) -> str:
        return canonical_json(self.data)

    @property
    def state_changing(self) -> bool:
        """Any step can change state (its method is not GET/HEAD), or the agent said so."""
        return self.declared_state_changing or any(s.method not in SAFE_METHODS for s in self.steps)

    @property
    def probe(self) -> str:
        """The label every capture of a run carries (``probe`` on the capture)."""
        return f"recipe:{self.name}"

    def identities(self) -> list[str]:
        return sorted({s.identity for s in self.steps if s.identity})

    def max_requests(self) -> int:
        return len(self.steps) + RUN_MARGIN

    def approval_view(self) -> dict[str, Any]:
        """What the operator reads before allowing a run: header names, never values."""
        steps = []
        for step in self.steps:
            body = step.body
            preview = "" if body is None else body if isinstance(body, str) else json.dumps(body)
            steps.append(
                {
                    "id": step.id,
                    "method": step.method,
                    "url": step.url,
                    "identity": step.identity,
                    "header_names": sorted(step.headers),
                    "body_preview": preview[:400],
                }
            )
        return {
            "recipe": self.name,
            "class": self.vuln_class,
            "title": self.title,
            "endpoint": self.endpoint,
            "identities": self.identities(),
            "declared_state_changing": self.declared_state_changing,
            "steps": steps,
        }


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ── validation ───────────────────────────────────────────────────────


def _str(value: Any, path: str, limit: int, *, required: bool = True, minimum: int = 0) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str):
        raise RecipeError(path, "must be a string")
    if required and not value.strip():
        raise RecipeError(path, "is required")
    if len(value) > limit:
        raise RecipeError(path, f"is longer than {limit} characters")
    if len(value.strip()) < minimum:
        raise RecipeError(path, f"must be at least {minimum} characters")
    return value


def _slug(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SLUG.match(value):
        raise RecipeError(
            path, "must be 1-41 characters of a-z, 0-9, _ and -, starting with a letter or digit"
        )
    return value


def _obj(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecipeError(path, "must be an object")
    return value


def _no_unknown(
    value: dict[str, Any], allowed: frozenset[str] | tuple[str, ...], path: str
) -> None:
    for key in value:
        if key not in allowed:
            raise RecipeError(
                f"{path}.{key}" if path else str(key),
                f"unknown key (allowed: {', '.join(sorted(allowed))})",
            )


def _statuses(value: Any, path: str) -> list[int]:
    items = value if isinstance(value, list) else [value]
    if not items or len(items) > 20:
        raise RecipeError(path, "must be a status code or a list of 1-20 status codes")
    for item in items:
        if isinstance(item, bool) or not isinstance(item, int) or not 100 <= item <= 599:
            raise RecipeError(path, "must be a status code (100-599) or a list of them")
    return list(items)


def _strings(value: Any, path: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_EXPECT_STRINGS:
        raise RecipeError(path, f"must be a list of at most {MAX_EXPECT_STRINGS} strings")
    for index, item in enumerate(value):
        _str(item, f"{path}[{index}]", MAX_SHORT)
    return list(value)


def placeholders(template: str) -> list[tuple[str, list[str]]]:
    """``(variable, pipes)`` for every ``{{...}}`` in ``template``."""
    out = []
    for match in PLACEHOLDER.finditer(template):
        parts = [p.strip() for p in match.group(1).split("|")]
        out.append((parts[0], parts[1:]))
    return out


def _check_template(template: str, path: str, defined: set[str]) -> None:
    for variable, pipes in placeholders(template):
        if variable not in BUILTINS and variable not in defined:
            raise RecipeError(
                path,
                f"unknown variable {variable!r}: use one extracted by an earlier step "
                f"or a built-in ({', '.join(BUILTINS)})",
            )
        for pipe in pipes:
            if pipe not in PIPES:
                raise RecipeError(
                    path, f"unknown pipe {pipe!r} (known: {', '.join(sorted(PIPES))})"
                )


def _check_body_templates(body: Any, path: str, defined: set[str]) -> None:
    if isinstance(body, str):
        _check_template(body, path, defined)
    elif isinstance(body, dict):
        for key, value in body.items():
            _check_template(str(key), f"{path}.{key}", defined)
            _check_body_templates(value, f"{path}.{key}", defined)
    elif isinstance(body, list):
        for index, value in enumerate(body):
            _check_body_templates(value, f"{path}[{index}]", defined)


def _authority(url: str) -> str:
    """``scheme://host[:port]`` of a URL as written, lower-cased; ``""`` without one."""
    match = _AUTHORITY.match(url)
    return f"{match.group(1)}://{match.group(2)}".lower() if match and match.group(2) else ""


def _url(value: Any, path: str, defined: set[str]) -> str:
    url = _str(value, path, MAX_URL)
    match = _AUTHORITY.match(url)
    if match is None or not match.group(2):
        raise RecipeError(path, "must be an absolute http(s) URL")
    authority = match.group(2)
    if "{" in authority or "}" in authority:
        raise RecipeError(
            path, "the host of every step must be literal: no {{...}} before the path"
        )
    if "@" in authority:
        raise RecipeError(path, "credentials in the URL are not accepted; use a header")
    if any(ch in url for ch in "\r\n\t "):
        raise RecipeError(path, "must not contain whitespace")
    _check_template(url, path, defined)
    return url


def _extract(value: Any, path: str, defined: set[str]) -> dict[str, dict[str, str]]:
    rules = _obj(value, path)
    if len(rules) > MAX_EXTRACT:
        raise RecipeError(path, f"at most {MAX_EXTRACT} variables per step")
    out: dict[str, dict[str, str]] = {}
    for name, rule in rules.items():
        where = f"{path}.{name}"
        if not VAR.match(str(name)) or name in BUILTINS:
            raise RecipeError(
                where,
                "a variable name is 1-41 letters, digits and _, not starting with a digit, "
                f"and not a built-in ({', '.join(BUILTINS)})",
            )
        if name in defined:
            raise RecipeError(where, f"variable {name!r} is already defined by an earlier step")
        rule = _obj(rule, where)
        source = rule.get("from")
        if source not in EXTRACT_FROM:
            raise RecipeError(f"{where}.from", f"must be one of {', '.join(EXTRACT_FROM)}")
        field = EXTRACT_FROM[source]
        _no_unknown(rule, ("from", field) if field else ("from",), where)
        clean = {"from": str(source)}
        if field:
            limit = MAX_PATTERN if field == "pattern" else MAX_PATH
            clean[field] = _str(rule.get(field), f"{where}.{field}", limit)
        if source == "regex":
            try:
                re.compile(clean["pattern"])
                if _NESTED_REPEAT.search(clean["pattern"]):
                    raise RecipeError(
                        f"{where}.pattern",
                        "a repeated group that itself contains a repeat can take unbounded "
                        "time on a long response; write the pattern without nesting repeats",
                    )
            except re.error as exc:
                raise RecipeError(f"{where}.pattern", f"does not compile: {exc}") from exc
        if source == "header" and not HEADER_NAME.match(clean["name"]):
            raise RecipeError(f"{where}.name", "must be an HTTP header name")
        out[str(name)] = clean
    return out


def _expect(value: Any, path: str, defined: set[str]) -> dict[str, Any]:
    expect = _obj(value, path)
    _no_unknown(expect, EXPECT_KEYS, path)
    out: dict[str, Any] = {}
    if "status" in expect:
        out["status"] = _statuses(expect["status"], f"{path}.status")
    for key in ("body_contains", "body_not_contains"):
        if key in expect:
            out[key] = _strings(expect[key], f"{path}.{key}")
            for index, needle in enumerate(out[key]):
                _check_template(needle, f"{path}.{key}[{index}]", defined)
    if not out:
        raise RecipeError(path, "is empty: give status, body_contains or body_not_contains")
    return out


def _step(value: Any, path: str, defined: set[str], seen: set[str]) -> Step:
    raw = _obj(value, path)
    _no_unknown(raw, STEP_KEYS, path)
    step_id = _slug(raw.get("id"), f"{path}.id")
    if step_id in seen:
        raise RecipeError(f"{path}.id", f"step id {step_id!r} is used twice")
    method = raw.get("method")
    if not isinstance(method, str) or method.upper() not in METHODS:
        raise RecipeError(f"{path}.method", f"must be one of {', '.join(METHODS)}")
    method = method.upper()
    url = _url(raw.get("url"), f"{path}.url", defined)

    headers: dict[str, str] = {}
    if raw.get("headers") is not None:
        given = _obj(raw["headers"], f"{path}.headers")
        if len(given) > MAX_HEADERS:
            raise RecipeError(f"{path}.headers", f"at most {MAX_HEADERS} headers")
        for name, header_value in given.items():
            where = f"{path}.headers.{name}"
            if not HEADER_NAME.match(str(name)):
                raise RecipeError(where, "is not a valid HTTP header name")
            header_value = _str(header_value, where, MAX_HEADER_VALUE, required=False)
            if "\r" in header_value or "\n" in header_value:
                raise RecipeError(where, "must not contain a line break")
            _check_template(header_value, where, defined)
            headers[str(name)] = header_value

    body = raw.get("body")
    if body is not None:
        if not isinstance(body, (str, dict, list)):
            raise RecipeError(f"{path}.body", "must be a string or a JSON object/array")
        size = len(body.encode() if isinstance(body, str) else canonical_json(body).encode())
        if size > MAX_BODY:
            raise RecipeError(f"{path}.body", f"is larger than {MAX_BODY} bytes")
        _check_body_templates(body, f"{path}.body", defined)
        if method in ("GET", "HEAD"):
            raise RecipeError(f"{path}.body", f"a {method} request carries no body")

    identity = raw.get("identity")
    if identity is None or identity == "":
        identity = ""
    elif not isinstance(identity, str) or not IDENTITY.match(identity):
        raise RecipeError(
            f"{path}.identity", 'must be the name of a declared test account, or "" for none'
        )

    expect = _expect(raw["expect"], f"{path}.expect", defined) if "expect" in raw else {}
    extract = _extract(raw["extract"], f"{path}.extract", defined) if "extract" in raw else {}
    seen.add(step_id)
    defined.update(extract)
    return Step(step_id, method, url, headers, body, identity, extract, expect)


def _condition(value: Any, path: str, steps: list[str], defined: set[str]) -> dict[str, Any]:
    raw = _obj(value, path)
    step = raw.get("step")
    if step not in steps:
        raise RecipeError(f"{path}.step", f"must name a step of this recipe ({', '.join(steps)})")
    kinds = [k for k in CONDITION_KINDS if k in raw]
    if len(kinds) != 1:
        raise RecipeError(path, f"needs exactly one of {', '.join(CONDITION_KINDS)}")
    kind = kinds[0]
    allowed: tuple[str, ...] = ("step", kind, *COMPARATORS) if kind == "json" else ("step", kind)
    _no_unknown(raw, allowed, path)
    out: dict[str, Any] = {"step": step}
    if kind == "status":
        out["status"] = _statuses(raw["status"], f"{path}.status")
    elif kind in ("body_contains", "body_not_contains"):
        out[kind] = _str(raw[kind], f"{path}.{kind}", MAX_SHORT)
        _check_template(out[kind], f"{path}.{kind}", defined)
    elif kind in ("same_as", "differs_from"):
        other = raw[kind]
        if other not in steps:
            raise RecipeError(f"{path}.{kind}", f"must name a step ({', '.join(steps)})")
        if other == step:
            raise RecipeError(f"{path}.{kind}", "must name another step")
        out[kind] = other
    else:
        out["json"] = _str(raw["json"], f"{path}.json", MAX_PATH)
        comparators = [c for c in COMPARATORS if c in raw]
        if len(comparators) != 1:
            raise RecipeError(
                path, f"a json condition needs exactly one of {', '.join(COMPARATORS)}"
            )
        comparator = comparators[0]
        expected = raw[comparator]
        if comparator in ("gt", "lt") and (
            isinstance(expected, bool) or not isinstance(expected, (int, float))
        ):
            raise RecipeError(f"{path}.{comparator}", "must be a number")
        if comparator == "equals":
            if len(canonical_json(expected)) > MAX_SHORT:
                raise RecipeError(f"{path}.equals", f"is longer than {MAX_SHORT} characters")
        out[comparator] = expected
    return out


def validate(recipe: Any) -> Recipe:
    """A :class:`Recipe`, or :class:`RecipeError` naming the first problem's exact path."""
    raw = _obj(recipe, "recipe")
    _no_unknown(raw, RECIPE_KEYS, "")
    name = _slug(raw.get("name"), "name")
    vuln_class = raw.get("class")
    if vuln_class not in CLASSES:
        raise RecipeError("class", f"must be one of {', '.join(CLASSES)}")
    title = _str(raw.get("title"), "title", MAX_TITLE)
    endpoint = _str(raw.get("endpoint"), "endpoint", MAX_URL)
    parameter = _str(raw.get("parameter"), "parameter", MAX_SHORT, required=False)
    remediation = _str(raw.get("remediation"), "remediation", MAX_TEXT, minimum=MIN_REMEDIATION)
    invariant = _str(raw.get("invariant"), "invariant", MAX_TITLE, required=False).strip()
    declared = raw.get("state_changing", False)
    if not isinstance(declared, bool):
        raise RecipeError("state_changing", "must be true or false")

    steps_raw = raw.get("steps")
    if not isinstance(steps_raw, list) or not 1 <= len(steps_raw) <= MAX_STEPS:
        raise RecipeError("steps", f"must be a list of 1-{MAX_STEPS} steps")
    defined: set[str] = set()
    seen: set[str] = set()
    steps = [_step(s, f"steps[{i}]", defined, seen) for i, s in enumerate(steps_raw)]
    step_ids = [s.id for s in steps]

    if _authority(endpoint) not in {_authority(s.url) for s in steps}:
        raise RecipeError("endpoint", "must be an absolute URL on a host one of the steps sends to")

    verdict = _obj(raw.get("verdict"), "verdict")
    _no_unknown(verdict, ("vulnerable_if", "control"), "verdict")
    conditions: dict[str, list[dict[str, Any]]] = {}
    for key in ("vulnerable_if", "control"):
        items = verdict.get(key)
        if not isinstance(items, list):
            raise RecipeError(f"verdict.{key}", "must be a list of conditions")
        if not items:
            raise RecipeError(
                f"verdict.{key}",
                CONTROL_REQUIRED if key == "control" else "needs at least one condition",
            )
        conditions[key] = [
            _condition(c, f"verdict.{key}[{i}]", step_ids, defined) for i, c in enumerate(items)
        ]
    if len(conditions["vulnerable_if"]) + len(conditions["control"]) > MAX_CONDITIONS:
        raise RecipeError("verdict", f"at most {MAX_CONDITIONS} conditions in all")

    data: dict[str, Any] = {
        "name": name,
        "class": vuln_class,
        "title": title,
        "endpoint": endpoint,
        "remediation": remediation,
        "steps": [_step_data(s) for s in steps],
        "verdict": conditions,
    }
    if parameter:
        data["parameter"] = parameter
    if invariant:
        data["invariant"] = invariant
    if declared:
        data["state_changing"] = True
    return Recipe(
        name=name,
        vuln_class=str(vuln_class),
        title=title,
        endpoint=endpoint,
        parameter=parameter,
        remediation=remediation,
        steps=tuple(steps),
        vulnerable_if=tuple(conditions["vulnerable_if"]),
        control=tuple(conditions["control"]),
        declared_state_changing=declared,
        data=data,
    )


def _step_data(step: Step) -> dict[str, Any]:
    out: dict[str, Any] = {"id": step.id, "method": step.method, "url": step.url}
    if step.headers:
        out["headers"] = dict(step.headers)
    if step.body is not None:
        out["body"] = step.body
    if step.identity:
        out["identity"] = step.identity
    if step.extract:
        out["extract"] = step.extract
    if step.expect:
        out["expect"] = step.expect
    return out


def parse(raw: str | dict[str, Any]) -> Recipe:
    """``raw`` (JSON text or an object) validated; :class:`RecipeError` otherwise."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RecipeError("recipe", f"is not valid JSON: {exc}") from exc
    return validate(raw)


def check(raw: str | dict[str, Any]) -> dict[str, Any]:
    """Validation only, as the agent reads it. Sends nothing."""
    try:
        recipe = parse(raw)
    except RecipeError as exc:
        return {"ok": False, "errors": [exc.to_dict()]}
    return {"ok": True, "state_changing": recipe.state_changing, "steps": len(recipe.steps)}


# ── templating ───────────────────────────────────────────────────────


def render(template: str, variables: dict[str, str]) -> str:
    """``template`` with every placeholder replaced; validation has checked every name."""

    def replace(match: re.Match[str]) -> str:
        parts = [p.strip() for p in match.group(1).split("|")]
        if parts[0] not in variables:
            raise RecipeError("template", f"unknown variable {parts[0]!r}")
        value = variables[parts[0]]
        for pipe in parts[1:]:
            if pipe not in PIPES:
                raise RecipeError("template", f"unknown pipe {pipe!r}")
            value = PIPES[pipe](value)
        return value

    return PLACEHOLDER.sub(replace, template)


def _render_body(body: Any, variables: dict[str, str]) -> Any:
    if isinstance(body, str):
        return render(body, variables)
    if isinstance(body, dict):
        return {render(str(k), variables): _render_body(v, variables) for k, v in body.items()}
    if isinstance(body, list):
        return [_render_body(v, variables) for v in body]
    return body


def builtins_for_run() -> dict[str, str]:
    alphabet = string.ascii_lowercase + string.digits
    return {
        "rand": "".join(secrets.choice(alphabet) for _ in range(8)),
        "ts": str(int(time.time())),
    }


# ── extraction and conditions ────────────────────────────────────────


def json_path(document: Any, path: str) -> tuple[bool, Any]:
    """``(found, value)`` at a dotted path; a numeric segment indexes a list."""
    cursor = document
    for part in path.split(".") if path else []:
        if isinstance(cursor, dict) and part in cursor:
            cursor = cursor[part]
        elif isinstance(cursor, list) and part.lstrip("-").isdigit():
            index = int(part)
            if not -len(cursor) <= index < len(cursor):
                return False, None
            cursor = cursor[index]
        else:
            return False, None
    return True, cursor


def _body(capture: Capture) -> str:
    return text(capture)[:SCAN_LIMIT]


def _json_body(capture: Capture) -> Any:
    try:
        return json.loads(text(capture))
    except ValueError:
        return None


def _as_value(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True)


def extract(rule: dict[str, str], capture: Capture) -> str | None:
    """The value a rule takes from a response, or ``None`` when it is not there."""
    source = rule["from"]
    if source == "status":
        return None if capture.status is None else str(capture.status)
    if source == "header":
        wanted = rule["name"].lower()
        for key, value in capture.response_headers.items():
            if key.lower() == wanted:
                return value.split("\n")[0][:MAX_VALUE]
        return None
    if source == "json":
        found, value = json_path(_json_body(capture), rule["path"])
        return _as_value(value)[:MAX_VALUE] if found and value is not None else None
    match = re.search(rule["pattern"], _body(capture))
    if match is None:
        return None
    return (match.group(1) if match.groups() else match.group(0) or "")[:MAX_VALUE]


def _has_response(capture: Capture) -> bool:
    return capture.status is not None and not capture.error


def condition_holds(
    condition: dict[str, Any], captures: dict[str, Capture], variables: dict[str, str]
) -> bool:
    capture = captures[condition["step"]]
    if not _has_response(capture):
        return False
    if "status" in condition:
        return capture.status in condition["status"]
    if "body_contains" in condition:
        return render(condition["body_contains"], variables) in _body(capture)
    if "body_not_contains" in condition:
        return render(condition["body_not_contains"], variables) not in _body(capture)
    if "same_as" in condition:
        other = captures[condition["same_as"]]
        return _has_response(other) and similarity(capture, other) >= SAME_AS_MIN
    if "differs_from" in condition:
        other = captures[condition["differs_from"]]
        return _has_response(other) and (
            similarity(capture, other) < DIFFERS_BELOW or capture.status != other.status
        )
    found, value = json_path(_json_body(capture), condition["json"])
    if not found:
        return False
    if "equals" in condition:
        return value == condition["equals"]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return value > condition["gt"] if "gt" in condition else value < condition["lt"]


def _kind(condition: dict[str, Any]) -> str:
    return next(k for k in CONDITION_KINDS if k in condition)


def _expect_failure(expect: dict[str, Any], capture: Capture, variables: dict[str, str]) -> str:
    """Why a step's expectation failed, without quoting any extracted value; "" when it holds."""
    if "status" in expect and capture.status not in expect["status"]:
        wanted = " or ".join(str(s) for s in expect["status"])
        return f"status {capture.status}, expected {wanted}"
    body = _body(capture)
    for index, needle in enumerate(expect.get("body_contains") or []):
        if render(needle, variables) not in body:
            return f"the body does not contain body_contains[{index}]"
    for index, needle in enumerate(expect.get("body_not_contains") or []):
        if render(needle, variables) in body:
            return f"the body contains body_not_contains[{index}]"
    return ""


# ── running ──────────────────────────────────────────────────────────


def run(
    gateway: CaptureGateway,
    engagement: str,
    recipe: Recipe,
    *,
    grant: ProbeGrant | None = None,
) -> dict[str, Any]:
    """Send the recipe's steps through the gateway in order and decide.

    A gateway refusal of a step comes back as the gateway's refusal dict (with
    the recipe, the step and what was already sent). Extracted values are
    never part of the result: only the variables' names are.
    """
    variables = builtins_for_run()
    captures: dict[str, Capture] = {}
    steps_out: list[dict[str, Any]] = []
    order: list[str] = []

    def finish(
        outcome: str, summary: str, conditions: list[dict[str, Any]] | None = None
    ) -> dict[str, Any]:
        vulnerable = {VULNERABLE: True, NOT_VULNERABLE: False}.get(outcome)
        return {
            "status": "completed",
            "recipe": recipe.name,
            "class": recipe.vuln_class,
            "vulnerable": vulnerable,
            "outcome": outcome,
            "summary": summary,
            "evidence_capture_ids": [captures[s].id for s in order],
            "steps": steps_out,
            "conditions": conditions or [],
            "variables": sorted(v for v in variables if v not in BUILTINS),
            "details": {"captures": {s: captures[s].id for s in order}},
        }

    for step in recipe.steps:
        url = render(step.url, variables)
        if any(ord(ch) < 0x20 or ch in " \x7f" for ch in url):
            return finish(
                PRECONDITION_FAILED,
                f"Step {step.id} was not sent: a value taken from an earlier response "
                "cannot be placed in its URL.",
            )
        headers = {name: render(value, variables) for name, value in step.headers.items()}
        body: str | None = None
        if isinstance(step.body, str):
            body = render(step.body, variables)
        elif step.body is not None:
            body = json.dumps(_render_body(step.body, variables))
            if not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"
        try:
            capture = gateway.send(
                engagement,
                step.method,
                url,
                headers=headers,
                body=body,
                identity=step.identity,
                probe=recipe.probe,
                note=f"recipe {recipe.name} step {step.id}",
                grant=grant,
            )
        except GatewayRefusal as refusal:
            return {
                "recipe": recipe.name,
                "step": step.id,
                **refusal.to_dict(),
                "evidence_capture_ids": [captures[s].id for s in order],
            }
        captures[step.id] = capture
        order.append(step.id)
        entry: dict[str, Any] = {
            "id": step.id,
            "capture_id": capture.id,
            "status": capture.status,
            "expect_ok": True,
        }
        steps_out.append(entry)
        if not _has_response(capture):
            entry["expect_ok"] = not step.expect
            return finish(NOT_SENT, f"Step {step.id} got no response from the target.")
        failure = _expect_failure(step.expect, capture, variables) if step.expect else ""
        if failure:
            entry["expect_ok"] = False
            return finish(
                PRECONDITION_FAILED,
                f"Step {step.id} did not behave as the recipe expects ({failure}), so the check "
                "could not be made; this is not a finding.",
            )
        for name, rule in step.extract.items():
            value = extract(rule, capture)
            if value is None:
                entry["expect_ok"] = False
                return finish(
                    PRECONDITION_FAILED,
                    f"Step {step.id}: variable {name} could not be extracted "
                    f"({rule['from']}), so the check could not be made; this is not a finding.",
                )
            variables[name] = value

    conditions: list[dict[str, Any]] = []
    for role, group in (("control", recipe.control), ("vulnerable_if", recipe.vulnerable_if)):
        for condition in group:
            conditions.append(
                {
                    "role": role,
                    "kind": _kind(condition),
                    "step": condition["step"],
                    "held": condition_holds(condition, captures, variables),
                }
            )
    failed_controls = [c for c in conditions if c["role"] == "control" and not c["held"]]
    missed = [c for c in conditions if c["role"] == "vulnerable_if" and not c["held"]]
    if failed_controls:
        first = failed_controls[0]
        return finish(
            CONTROL_FAILED,
            f"A control did not hold ({first['kind']} on step {first['step']}), so the result "
            "cannot be trusted either way.",
            conditions,
        )
    if missed:
        first = missed[0]
        return finish(
            NOT_VULNERABLE,
            f"The controls held but {first['kind']} on step {first['step']} did not, so the "
            "target is not vulnerable to this check.",
            conditions,
        )
    return finish(
        VULNERABLE,
        f"Every control held and every vulnerable_if condition held: {recipe.title}.",
        conditions,
    )


def execute(gateway: CaptureGateway, engagement: str, recipe: Recipe) -> dict[str, Any]:
    """Check identities and scope, get the run approved if it can change state, then run it.

    Nothing is sent and no approval is filed when a named identity is unknown
    or a step's host is out of scope. A state-changing recipe, where the
    engagement requires approval, is approved as one run (one decision, capped
    at its step count plus :data:`RUN_MARGIN`).
    """
    try:
        for identity in recipe.identities():
            gateway.check_identity(engagement, identity)
        urls = [step.url for step in recipe.steps]
        grant = None
        if recipe.state_changing:
            grant = gateway.recipe_grant(
                engagement,
                recipe.name,
                recipe.canonical,
                urls,
                recipe.approval_view(),
                recipe.max_requests(),
            )
        else:
            for step in recipe.steps:
                gateway.check_target(engagement, step.url, step.method)
    except GatewayRefusal as refusal:
        return {"recipe": recipe.name, **refusal.to_dict()}
    return run(gateway, engagement, recipe, grant=grant)


__all__ = [
    "BUILTINS",
    "CONTROL_REQUIRED",
    "PIPES",
    "Recipe",
    "RecipeError",
    "Step",
    "canonical_json",
    "check",
    "execute",
    "extract",
    "json_path",
    "parse",
    "render",
    "run",
    "validate",
]
