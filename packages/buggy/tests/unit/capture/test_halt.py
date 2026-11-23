"""The operator's halt switch: the file, the epoch, and the gateway and browser that obey it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from buggy.capture import halt
from buggy.capture.gateway import CaptureGateway, GatewayRefusal, Roots
from buggy.cli import halt as halt_cli
from buggy.scoped_browser.session import ScopedBrowser


class Site:
    """Counts what would have been sent; answers 200."""

    def __init__(self) -> None:
        self.sent = 0

    def open(self, request, timeout=None):  # noqa: ARG002
        import io  # noqa: PLC0415

        self.sent += 1
        response = io.BytesIO(b"{}")
        response.status, response.headers = 200, {"Content-Type": "application/json"}
        response.__enter__ = lambda *_: response
        response.__exit__ = lambda *_: False
        return response


@pytest.fixture
def roots(tmp_path: Path) -> Roots:
    roots = Roots(control=tmp_path / "control", audit=tmp_path / "audit", data=tmp_path / "data")
    (roots.control / "acme").mkdir(parents=True)
    (roots.control / "acme" / "roe.json").write_text(
        json.dumps(
            {
                "machine_enforcement": {"mode": "enforce", "in_scope": ["app.acme.test"]},
                "approvals": {"state_changing": "not_required"},
            }
        )
    )
    return roots


class TestState:
    def test_absent_files_mean_running_at_epoch_zero(self, roots: Roots) -> None:
        assert halt.read_state(roots.control, "acme") == halt.HaltState(False, 0)
        assert halt.read_state(roots.control, "no-such-engagement").halted is False

    def test_halt_raises_the_epoch_and_clear_keeps_it(self, roots: Roots) -> None:
        state = halt.halt(roots.control, "acme", reason="client asked", by="op")
        assert state.halted and state.epoch == 1 and state.reason == "client asked"
        read = halt.read_state(roots.control, "acme")
        assert read.halted and read.epoch == 1 and read.by == "op" and read.at > 0
        assert halt.clear(roots.control, "acme") is True
        assert halt.read_state(roots.control, "acme") == halt.HaltState(False, 1)
        assert halt.clear(roots.control, "acme") is False
        assert halt.halt(roots.control, "acme").epoch == 2

    def test_a_halt_file_with_garbage_is_still_a_halt(self, roots: Roots) -> None:
        (roots.control / "acme" / halt.HALT_FILE).write_text("not json")
        state = halt.read_state(roots.control, "acme")
        assert state.halted and state.reason == ""

    @pytest.mark.parametrize("epoch", ["x", "-3", ""])
    def test_an_unreadable_epoch_is_an_error_not_zero(self, roots: Roots, epoch: str) -> None:
        (roots.control / "acme" / halt.EPOCH_FILE).write_text(epoch)
        with pytest.raises(halt.ControlStateError):
            halt.read_state(roots.control, "acme")

    def test_a_halt_that_cannot_be_read_is_an_error(self, roots: Roots) -> None:
        (roots.control / "acme" / halt.HALT_FILE).mkdir()  # a directory: reading fails
        with pytest.raises(halt.ControlStateError):
            halt.read_state(roots.control, "acme")


class TestGateway:
    def test_a_halted_engagement_sends_nothing_and_says_why(self, roots: Roots) -> None:
        site = Site()
        gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
        gateway.send("acme", "GET", "https://app.acme.test/a")
        assert site.sent == 1
        halt.halt(roots.control, "acme", reason="stop now")
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", "https://app.acme.test/b")
        assert refused.value.code == "HALTED" and "stop now" in refused.value.detail
        with pytest.raises(GatewayRefusal):
            gateway.check_target("acme", "https://app.acme.test/b")
        assert site.sent == 1
        ledger = (roots.audit / "acme" / "captures.jsonl").read_text()
        assert '"HALTED"' in ledger
        halt.clear(roots.control, "acme")
        gateway.send("acme", "GET", "https://app.acme.test/c")
        assert site.sent == 2
        gateway.store.close()

    def test_unreadable_halt_state_refuses(self, roots: Roots) -> None:
        site = Site()
        gateway = CaptureGateway(roots, opener=site, sleep=lambda _s: None)
        (roots.control / "acme" / halt.EPOCH_FILE).write_text("garbage")
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", "https://app.acme.test/a")
        assert refused.value.code == "HALT_STATE_UNREADABLE" and site.sent == 0
        gateway.store.close()

    def test_scope_is_checked_before_the_halt(self, roots: Roots) -> None:
        gateway = CaptureGateway(roots, opener=Site(), sleep=lambda _s: None)
        halt.halt(roots.control, "acme")
        with pytest.raises(GatewayRefusal) as refused:
            gateway.send("acme", "GET", "https://elsewhere.test/")
        assert refused.value.code == "OUT_OF_SCOPE"
        gateway.store.close()


def test_the_browser_obeys_the_halt(roots: Roots) -> None:
    browser = ScopedBrowser(roots.control, roots.audit)
    assert browser._decide("acme", "https://app.acme.test/", "GET")[0] is True  # noqa: SLF001
    halt.halt(roots.control, "acme")
    assert browser._decide("acme", "https://app.acme.test/", "GET") == (False, "HALTED")  # noqa: SLF001
    (roots.control / "acme" / halt.EPOCH_FILE).write_text("x")
    assert browser._decide("acme", "https://app.acme.test/", "GET") == (  # noqa: SLF001
        False,
        "HALT_STATE_UNREADABLE",
    )


class TestCli:
    def run(self, roots: Roots, capsys, *argv: str) -> tuple[int, str]:
        code = halt_cli.main(
            [*argv, "--control-root", str(roots.control), "--audit-root", str(roots.audit)]
        )
        captured = capsys.readouterr()
        return code, captured.out + captured.err

    def test_halt_show_and_clear(self, roots: Roots, capsys) -> None:
        lease = roots.audit / "acme" / "agent" / "leases"
        lease.mkdir(parents=True)
        (lease / "r1.json").write_text(json.dumps({"run": "r1", "ended_at": None}))
        (lease / "r0.json").write_text(json.dumps({"run": "r0", "ended_at": 5.0}))
        code, out = self.run(roots, capsys, "acme", "--reason", "client call")
        assert (
            code == 0 and "HALTED (epoch 1)" in out and "revoked 1 open agent lease(s): r1" in out
        )
        code, out = self.run(roots, capsys, "acme", "--show", "--json")
        shown = json.loads(out)
        assert (
            shown["halted"] and shown["reason"] == "client call" and shown["open_leases"] == ["r1"]
        )
        code, out = self.run(roots, capsys, "acme", "--clear")
        assert code == 0 and "halt lifted" in out and "stay stopped" in out
        assert halt.read_state(roots.control, "acme") == halt.HaltState(False, 1)

    @pytest.mark.parametrize("name", ["nope", "../acme", ".hidden"])
    def test_an_unknown_engagement_is_refused(self, roots: Roots, capsys, name: str) -> None:
        code, out = self.run(roots, capsys, name)
        assert code == halt_cli.EXIT_CONFIG and "no engagement" in out
