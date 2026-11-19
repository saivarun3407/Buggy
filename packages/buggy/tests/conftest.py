"""Suite-wide defaults for the framework tests.

Production defaults are fail-closed: a missing operator-controlled RoE refuses
every gated tool, and the control / audit roots are expected at ``/control``
and ``/audit``. Most unit tests exercise one behaviour against a throwaway
``tmp_path`` workspace with a draft ``plan/roe.json`` and no control plane, so
the suite runs with the documented lab opt-outs (``BUGGY_ROE_REQUIRE=0``,
``BUGGY_EGRESS_DISABLE=1`` - there is no sandbox or guard to provision) and
with the roots pointed at paths that do not exist.

Tests that cover the production posture set these variables themselves
(see ``unit/middleware/test_roe_control_plane.py`` and ``e2e/``).
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _lab_scope_defaults(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory):
    missing = tmp_path_factory.getbasetemp() / "no-control-plane"
    monkeypatch.setenv("BUGGY_ROE_REQUIRE", "0")
    monkeypatch.setenv("BUGGY_EGRESS_DISABLE", "1")
    monkeypatch.setenv("BUGGY_CONTROL_ROOT", str(missing / "control"))
    monkeypatch.setenv("BUGGY_AUDIT_ROOT", str(missing / "audit"))
    monkeypatch.delenv("BUGGY_EGRESS_GUARD_URL", raising=False)
    monkeypatch.delenv("EGRESS_GUARD_TOKEN", raising=False)
    yield
