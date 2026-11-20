"""The framework-free MCP client, against the real recon server over streamable HTTP.

The recon server is started in-process on a loopback port behind the same
bearer auth the containers serve (``buggy.pipeline.mcp_http.build_app``) and
called through ``buggy.pipeline.mcp_client``, the client the operator
commands use in the slim pipeline image. The last tests run ``buggy-cli hunt``
in a subprocess with the agent framework made unimportable, as it is there.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("mcp")
import uvicorn  # noqa: E402

from buggy.cli import hunt  # noqa: E402
from buggy.pipeline import mcp_client, service  # noqa: E402
from buggy.pipeline import mcp_server as recon_server  # noqa: E402
from buggy.pipeline.mcp_http import TOKEN_ENV, build_app  # noqa: E402
from buggy.pipeline.schema import Record, RecordType  # noqa: E402
from buggy.pipeline.store import ReconStore  # noqa: E402

STACK_TOKEN = "unit-test-stack-mcp-token-0123456789"  # noqa: S105 - test fixture
RECON_URL_ENV = "BUGGY_MCP_RECON_URL"
SERVICE_URL = "http://127.0.0.1/"

#: Makes the agent framework unimportable, then runs the code under test.
BLOCKED = ("langchain", "langchain_core", "langgraph")
BLOCK_PRELUDE = "import sys\n" + "".join(f"sys.modules[{name!r}] = None\n" for name in BLOCKED)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Server:
    def __init__(self, mcp, port: int) -> None:
        # The same app the containers serve: bearer auth included.
        config = uvicorn.Config(build_app(mcp), host="127.0.0.1", port=port, log_level="error")
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("MCP server did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture
def recon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    """A recon server holding one finished run for engagement ``acme``, token required."""
    control, data = tmp_path / "control", tmp_path / "data"
    monkeypatch.setenv(TOKEN_ENV, STACK_TOKEN)
    (control / "acme").mkdir(parents=True)
    (control / "acme" / "roe.json").write_text(
        json.dumps({"machine_enforcement": {"mode": "enforce", "in_scope": ["127.0.0.1"]}})
    )
    store = ReconStore(data / "pipeline" / service.STORE_FILE)
    run = store.begin_run("acme", trigger="test")
    store.write_records(
        run,
        "acme",
        "live",
        [(Record(RecordType.HTTP_SERVICE, "127.0.0.1", SERVICE_URL, "httpx"), "127.0.0.1")],
        tool_version="1.12.0",
        raw_ref="",
    )
    store.finish_run(run, status="completed", stats={})
    store.close()

    port = _free_port()
    server = _Server(
        recon_server.build_server(
            data_root=data / "pipeline",
            queue_root=data / "queue",
            control_root=control,
            port=port,
        ),
        port,
    )
    url = f"http://127.0.0.1:{port}/mcp"
    monkeypatch.setenv(RECON_URL_ENV, url)
    yield {"url": url, "control": control, "workspace": tmp_path / "workspace"}
    server.stop()


# ── the client ───────────────────────────────────────────────────────


def test_a_call_with_the_token_returns_the_servers_data(recon) -> None:
    summary = mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})
    assert "error" not in summary
    assert summary["engagement"] == "acme" and summary["records"] == {"http_service": 1}
    assert summary["last_run"]["status"] == "completed"

    page = mcp_client.call_mcp_sync(
        "recon", "recon_query", {"engagement": "acme", "record_type": "http_service"}
    )
    (record,) = page["records"]
    assert record["value"] == SERVICE_URL
    assert record["source_tool"] == "httpx" and record["tool_version"] == "1.12.0"


def test_without_the_token_the_result_is_an_error_and_no_data(recon, monkeypatch) -> None:
    # Control: the same call is answered while the token is held.
    assert "records" in mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})

    monkeypatch.delenv(TOKEN_ENV)
    refused = mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})
    assert set(refused) == {"error"} and "recon server call failed" in refused["error"]

    monkeypatch.setenv(TOKEN_ENV, "wrong-token-wrong-token-wrong")
    wrong = mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})
    assert set(wrong) == {"error"}

    monkeypatch.setenv(TOKEN_ENV, STACK_TOKEN)
    assert "records" in mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})


def test_an_unconfigured_server_is_reported_and_never_contacted(recon, monkeypatch) -> None:
    assert mcp_client.server_configured("recon") is True
    assert mcp_client.server_url("recon") == recon["url"]

    monkeypatch.delenv(RECON_URL_ENV)
    assert mcp_client.server_configured("recon") is False
    result = mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})
    assert set(result) == {"error"}
    assert "not configured" in result["error"] and RECON_URL_ENV in result["error"]

    monkeypatch.setenv(RECON_URL_ENV, "   ")
    assert mcp_client.server_configured("recon") is False
    # A server that was never part of this stack is not configured either.
    monkeypatch.delenv("BUGGY_MCP_CAPTURE_URL", raising=False)
    assert mcp_client.server_configured("capture") is False


def test_an_unreachable_server_is_an_error_result_not_an_exception(monkeypatch) -> None:
    monkeypatch.setenv(TOKEN_ENV, STACK_TOKEN)
    monkeypatch.setenv(RECON_URL_ENV, f"http://127.0.0.1:{_free_port()}/mcp")
    assert mcp_client.server_configured("recon") is True  # configured, just not answering
    result = mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})
    assert set(result) == {"error"} and "recon server call failed" in result["error"]


def test_a_tool_the_server_does_not_have_is_an_error_result(recon) -> None:
    result = mcp_client.call_mcp_sync("recon", "no_such_tool", {"engagement": "acme"})
    assert set(result) == {"error"}


async def test_the_blocking_call_is_safe_inside_a_running_event_loop(recon) -> None:
    summary = mcp_client.call_mcp_sync("recon", "recon_summary", {"engagement": "acme"})
    assert summary["records"] == {"http_service": 1}


def test_env_names_match_the_agent_side_client() -> None:
    pytest.importorskip("langchain_core")
    from buggy.tools import stack_mcp  # noqa: PLC0415

    assert mcp_client.SERVER_ENV == stack_mcp.SERVER_ENV
    assert mcp_client.CALL_TIMEOUT_SECONDS == stack_mcp.CALL_TIMEOUT_SECONDS


# ── hunt uses it ─────────────────────────────────────────────────────


def test_hunt_reads_recon_through_this_client(recon, monkeypatch) -> None:
    assert hunt.recon_available() is True
    assert hunt._recon("recon_summary", "acme")["records"] == {"http_service": 1}
    page = hunt._recon("recon_query", "acme", record_type="http_service", limit=5)
    assert [r["value"] for r in page["records"]] == [SERVICE_URL]
    assert hunt.collect_records("acme")["http_service"][0]["value"] == SERVICE_URL

    monkeypatch.delenv(RECON_URL_ENV)
    assert hunt.recon_available() is False
    assert "not configured" in hunt._recon("recon_summary", "acme")["error"]


# ── without the agent framework ──────────────────────────────────────


def _run_blocked(code: str, cwd: Path, **env: str) -> subprocess.CompletedProcess[str]:
    """Run ``code`` in a fresh interpreter where the agent framework cannot be imported.

    ``BUGGY_SKIP_BOOT=1`` is what the slim pipeline image sets: the package
    is imported without the agent framework's boot step.
    """
    base = {k: v for k, v in os.environ.items() if not k.startswith("BUGGY_")}
    return subprocess.run(  # noqa: S603 - our own interpreter and a fixed script
        [sys.executable, "-c", BLOCK_PRELUDE + code],
        cwd=cwd,
        env={**base, "BUGGY_SKIP_BOOT": "1", **env},
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


HUNT_PLAN_ONLY = """
from buggy.cli import hunt
code = hunt.main(["https://app.example.test", "--plan-only", "--yes", "--engagement-name", "guard",
                  "--workspace-root", "workspace", "--control-root", "control"])
loaded = sorted(m for m in sys.modules if m.split(".")[0] in {"langchain", "langchain_core",
                "langgraph"} and sys.modules[m] is not None)
assert not loaded, loaded
assert "buggy.tools.stack_mcp" not in sys.modules and "buggy.middleware" not in sys.modules
raise SystemExit(code)
"""


def test_hunt_plan_only_runs_with_the_agent_framework_blocked(tmp_path: Path) -> None:
    result = _run_blocked(HUNT_PLAN_ONLY, tmp_path)
    assert result.returncode == 0, result.stderr
    assert "--plan-only: scope written, nothing started" in result.stderr
    enforced = json.loads((tmp_path / "control" / "guard" / "roe.json").read_text())
    assert enforced["machine_enforcement"]["mode"] == "enforce"
    assert enforced["machine_enforcement"]["in_scope"] == ["app.example.test"]
    assert (tmp_path / "workspace" / "guard" / "plan" / "roe.json").is_file()


def test_the_scope_validator_still_refuses_a_bad_pattern_without_the_framework(
    tmp_path: Path,
) -> None:
    """The guardrail's own entry validator runs in the slim image too; it is not skipped."""
    code = HUNT_PLAN_ONLY.replace('"--plan-only"', '"--scope", "http://", "--plan-only"')
    assert code != HUNT_PLAN_ONLY
    result = _run_blocked(code, tmp_path)
    assert result.returncode == hunt.EXIT_CONFIG, result.stderr
    # This message comes from the guardrail's validator, not from hunt's own pattern check.
    assert "in_scope 'http://': RoE in_scope contains an unsupported URL target" in result.stderr
    assert not (tmp_path / "control").exists(), "a refused scope must not be written"


def test_the_cli_validates_scope_with_the_guardrails_own_function() -> None:
    """engage imports the validator from buggy_core; the guardrail must be using the same one."""
    pytest.importorskip("langchain")
    from buggy.cli import engage  # noqa: PLC0415
    from buggy.middleware import roe  # noqa: PLC0415
    from buggy_core.types import roe_document  # noqa: PLC0415

    assert roe._validate_target_entry is roe_document._validate_target_entry
    assert roe.InvalidRoEError is roe_document.InvalidRoEError
    assert engage._validate_scope_entries(["app.example.test", "10.0.0.0/8"], []) == []
    (error,) = engage._validate_scope_entries(["app.example.test"], ["10.0.0.0/99"])
    assert error.startswith("out_of_scope '10.0.0.0/99':")


def test_the_block_is_real_the_agent_side_client_cannot_be_imported(tmp_path: Path) -> None:
    """Negative control: under the same block, what hunt used before does not import."""
    result = _run_blocked("import buggy.tools.stack_mcp\n", tmp_path)
    assert result.returncode != 0
    assert "ImportError" in result.stderr or "ModuleNotFoundError" in result.stderr

    ok = _run_blocked("import buggy.pipeline.mcp_client, buggy.cli.hunt\n", tmp_path)
    assert ok.returncode == 0, ok.stderr


def test_hunt_no_agent_watches_recon_and_writes_the_report_without_the_framework(
    recon, tmp_path: Path
) -> None:
    code = f"""
from buggy.cli import hunt
code = hunt.main(["http://127.0.0.1/", "--no-agent", "--yes", "--non-interactive",
                  "--engagement-name", "acme", "--recon-timeout", "0",
                  "--workspace-root", {str(recon["workspace"])!r},
                  "--control-root", {str(recon["control"])!r}])
assert "buggy.tools.stack_mcp" not in sys.modules
raise SystemExit(code)
"""
    result = _run_blocked(code, tmp_path, **{RECON_URL_ENV: recon["url"], TOKEN_ENV: STACK_TOKEN})
    assert result.returncode == 0, result.stderr
    assert "agents skipped (--no-agent)" in result.stderr
    assert "recon unavailable" not in result.stderr

    report = recon["control"] / "acme" / "recon-report.md"
    assert SERVICE_URL in report.read_text(encoding="utf-8")
    event = json.loads(result.stdout.strip().splitlines()[-1])
    assert event["type"] == "recon_report" and event["services"] == 1
    assert Path(event["path"]) == report


def test_hunt_no_agent_without_the_token_says_recon_is_unavailable(recon, tmp_path: Path) -> None:
    """Negative control for the test above: no token, no recon data, no report."""
    code = f"""
from buggy.cli import hunt
raise SystemExit(hunt.main(["http://127.0.0.1/", "--no-agent", "--yes", "--non-interactive",
                            "--engagement-name", "acme", "--recon-timeout", "0",
                            "--workspace-root", {str(recon["workspace"])!r},
                            "--control-root", {str(recon["control"])!r}]))
"""
    result = _run_blocked(code, tmp_path, **{RECON_URL_ENV: recon["url"]})
    assert result.returncode == 0, result.stderr
    assert "recon unavailable" in result.stderr
    assert not (recon["control"] / "acme" / "recon-report.md").exists()
    assert result.stdout.strip() == ""
