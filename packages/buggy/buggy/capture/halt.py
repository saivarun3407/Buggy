"""The operator's halt switch for one engagement, and the epoch agent runs are leased on.

    <control>/<engagement>/HALT         present: the engagement is halted
    <control>/<engagement>/halt-epoch   how many times it was halted (an integer)

Both live under the operator-controlled root, which agents can read but never
write; only ``buggy-cli halt`` writes them. While ``HALT`` exists, the evidence
gateway sends nothing for the engagement (every built-in agent, probe and
outside agent goes through it) and the agent bridge refuses every tool call.

An agent run (the bridge) notes the epoch when it starts. Every halt raises
the epoch, so a run that started before a halt stays revoked after
``buggy-cli halt --clear``: clearing lets new runs start, it never revives an
old one.

Fail closed: a control state that cannot be read raises
:class:`ControlStateError`, and every caller treats that as a refusal. A file
that is simply absent is the normal "not halted" / "epoch 0".
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

HALT_FILE = "HALT"
EPOCH_FILE = "halt-epoch"
MAX_REASON = 500


class ControlStateError(Exception):
    """The halt state of an engagement exists but cannot be read."""


@dataclass(frozen=True, slots=True)
class HaltState:
    halted: bool
    epoch: int
    reason: str = ""
    at: float = 0.0
    by: str = ""


def _read_text(path: Path) -> str | None:
    """The file's text, ``None`` when it does not exist; anything else raises."""
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, UnicodeDecodeError) as exc:
        raise ControlStateError(f"{path.name}: {type(exc).__name__}") from exc


def read_state(control: Path, engagement: str) -> HaltState:
    """The engagement's halt state. Raises :class:`ControlStateError` when unreadable."""
    directory = control / engagement
    raw_epoch = _read_text(directory / EPOCH_FILE)
    if raw_epoch is None:
        epoch = 0
    else:
        try:
            epoch = int(raw_epoch.strip())
        except ValueError as exc:
            raise ControlStateError(f"{EPOCH_FILE}: not an integer") from exc
        if epoch < 0:
            raise ControlStateError(f"{EPOCH_FILE}: negative")
    raw_halt = _read_text(directory / HALT_FILE)
    if raw_halt is None:
        return HaltState(False, epoch)
    # The file's presence is the halt; its content only explains it.
    try:
        record = json.loads(raw_halt)
    except ValueError:
        record = {}
    record = record if isinstance(record, dict) else {}
    try:
        at = float(record.get("at") or 0.0)
    except (TypeError, ValueError):
        at = 0.0
    return HaltState(
        True,
        epoch,
        reason=str(record.get("reason") or "")[:MAX_REASON],
        at=at,
        by=str(record.get("by") or "")[:80],
    )


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def halt(control: Path, engagement: str, *, reason: str = "", by: str = "") -> HaltState:
    """Halt the engagement: raise the epoch (revoking every running lease), then write HALT."""
    current = read_state(control, engagement)
    epoch = current.epoch + 1
    now = time.time()
    _write_atomic(control / engagement / EPOCH_FILE, f"{epoch}\n")
    record = {"reason": reason[:MAX_REASON], "at": now, "by": by[:80], "epoch": epoch}
    _write_atomic(control / engagement / HALT_FILE, json.dumps(record) + "\n")
    return HaltState(True, epoch, reason=record["reason"], at=now, by=record["by"])


def clear(control: Path, engagement: str) -> bool:
    """Lift the halt for new runs. Returns whether there was one. The epoch stays."""
    try:
        (control / engagement / HALT_FILE).unlink()
    except FileNotFoundError:
        return False
    return True


def refusal_text(engagement: str, state: HaltState) -> str:
    """What a refused caller is told."""
    why = f" ({state.reason})" if state.reason else ""
    return f"the operator halted engagement {engagement}{why}; nothing is sent until they lift it"


__all__ = [
    "EPOCH_FILE",
    "HALT_FILE",
    "ControlStateError",
    "HaltState",
    "clear",
    "halt",
    "read_state",
    "refusal_text",
]
