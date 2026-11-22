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
        # A whole interpolated segment is an object id: the path is a template.
        ("${base}/api/users/${id}", "/api/users/{id}"),
        ("${base}/api/users/${id}/orders?page=${p}", "/api/users/{id}/orders?page="),
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


class TestObjectTemplates:
    """Per-object URLs a single-page app builds (taken from the Juice Shop bundle)."""

    JS = (
        'class A{constructor(e){this.hostServer=O.hostServer,this.host=this.hostServer+"/api/BasketItems"}'
        "find(e){return this.http.get(`${this.hostServer}/rest/basket/${e}`)}"
        "get(e){return this.http.get(`${this.host}/${e}`)}"
        "co(e){return this.http.post(`${this.hostServer}/rest/basket/${e}/checkout`,{})}"
        "del(e){return this.http.delete(`${this.host}/${e}`)}"
        "mid(e){return this.http.get(`${this.hostServer}/x${e}`)}}"
        'class B{constructor(){this.host=this.hostServer+"/api/Users"}'
        "get(e){return this.http.get(`${this.host}/${e}`)}}"
    )

    def test_a_whole_segment_becomes_a_placeholder_and_the_base_variable_is_resolved(self) -> None:
        found = jsparse.extract_literals(self.JS)
        assert "/rest/basket/{id}" in found and "/rest/basket/{id}/checkout" in found
        assert "/api/BasketItems/{id}" in found and "/api/Users/{id}" in found
        assert not [v for v in found if v.startswith("/x")]  # mid-segment: not in the text

    def test_the_method_of_the_call_is_kept_and_a_write_wins(self) -> None:
        methods = {
            r.value.rsplit("3000", 1)[1]: r.attrs.get("method")
            for r in jsparse.parse(self.JS, js_url="http://j.lab:3000/main.js")
        }
        assert methods["/rest/basket/{id}"] == "GET"
        assert methods["/rest/basket/{id}/checkout"] == "POST"
        assert methods["/api/BasketItems/{id}"] == "DELETE"  # GET and DELETE: never a plain read

    def test_the_user_walk_only_fills_templates_the_app_reads(self) -> None:
        from buggy.capture.journey import walk_plan

        records = [
            {"value": r.value, "type": "endpoint", "attrs": r.attrs}
            for r in jsparse.parse(self.JS, js_url="http://j.lab:3000/main.js")
        ]
        plan = walk_plan({"endpoint": records}, ["http://j.lab:3000/"])
        assert plan["templates"] == [
            "http://j.lab:3000/rest/basket/{id}",
            "http://j.lab:3000/api/Users/{id}",
        ]
