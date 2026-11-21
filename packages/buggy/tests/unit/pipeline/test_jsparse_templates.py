"""Paths and parameter names from interpolated template literals."""

from __future__ import annotations

import pytest

from buggy.pipeline.schema import RecordType
from buggy.pipeline.tools import jsparse, params

BUNDLE = (
    "class P{search(e){return this.http.get(`${this.hostServer}/rest/products/search?q=${e}`)"
    ".pipe(x)}find(a,b){return fetch(`${api}/orders?status=open&owner=${a}&page=${b}`)}"
    'old(){return this.http.get(this.host+"/rest/user/whoami")}}'
)


def test_the_path_and_parameter_names_of_a_template_are_found() -> None:
    literals = jsparse.extract_literals(BUNDLE)
    assert literals == [
        "/rest/user/whoami",
        "/rest/products/search?q=",
        "/orders?status=open&owner=&page=",
    ]


@pytest.mark.parametrize(
    ("template", "expected"),
    [
        ("${base}/api/items", "/api/items"),
        ("/api/items?id=${id}", "/api/items?id="),
        ("${a}/x/y?fixed=1", "/x/y?fixed=1"),
        # The path itself is interpolated: its real value is not in the text.
        ("${base}/api/users/${id}", None),
        ("${base}/api/users/${id}/orders?page=${p}", None),
        # Not a path, or nothing interpolated (plain literals are handled elsewhere).
        ("hello ${name}", None),
        ("/api/plain", None),
        ("${a}${b}", None),
        ("${base}//evil.test/x", None),
        ("${base}/x?${whole}", None),
        ("${base}/x?a=<b>", None),
    ],
)
def test_template_path(template: str, expected: str | None) -> None:
    assert jsparse._template_path(template) == expected  # noqa: SLF001


def test_nothing_is_invented_for_a_value() -> None:
    (literal,) = jsparse.extract_literals("f(`${h}/search?q=${encodeURIComponent(term)}`)")
    assert literal == "/search?q="


def test_static_files_and_noise_stay_out() -> None:
    script = "a(`${cdn}/img/logo.png?v=${v}`);b(`${x}/a`)"
    assert jsparse.extract_literals(script) == []


def test_the_limit_holds_across_both_passes() -> None:
    script = "".join(f'"/plain/{n}";' for n in range(5)) + "".join(
        f"`${{b}}/tpl/{n}?q=${{v}}`;" for n in range(5)
    )
    assert len(jsparse.extract_literals(script, limit=7)) == 7


def test_the_parameter_reaches_the_parameter_records() -> None:
    records = list(jsparse.parse(BUNDLE, js_url="https://shop.test/main.js"))
    urls = [r.value for r in records]
    assert "https://shop.test/rest/products/search?q=" in urls
    stored = [
        {"type": r.type.value, "value": r.value, "attrs": r.attrs, "source_tool": r.source_tool}
        for r in records
    ]
    found = {
        (p.attrs["url"], p.attrs["name"], p.attrs["location"])
        for p in params.extract(stored)
        if p.type is RecordType.PARAMETER
    }
    assert ("https://shop.test/rest/products/search", "q", "query") in found
    assert ("https://shop.test/orders", "owner", "query") in found
