"""Hash-chained JSONL ledger for egress decisions (standard library only).

Same chain shape as ``buggy.middleware._audit_sink`` (``seq``, ``prev_hash``,
``hash``, optional ``hmac``) so ``buggy-cli audit`` verifies both files.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


class Ledger:
    def __init__(self, path: Path, *, hmac_key: bytes | None = None) -> None:
        self.path = Path(path)
        if hmac_key is None:
            env_key = os.environ.get("BUGGY_AUDIT_HMAC_KEY")
            hmac_key = env_key.encode("utf-8") if env_key else None
        self._key = hmac_key
        self._lock = threading.Lock()
        self._seq = 0
        self._last = _GENESIS
        self._hydrate()

    def _hydrate(self) -> None:
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for raw in handle:
                    line = raw.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._seq = int(record.get("seq", self._seq))
                    self._last = str(record.get("hash", self._last))
        except FileNotFoundError:
            return

    def append(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            stamped = dict(record)
            stamped["seq"] = self._seq + 1
            payload = dict(stamped)
            payload["prev_hash"] = self._last
            digest = hashlib.sha256(_canonical(payload)).hexdigest()
            stamped["prev_hash"] = self._last
            stamped["hash"] = digest
            stamped["hmac"] = (
                hmac.new(self._key, digest.encode("ascii"), hashlib.sha256).hexdigest()
                if self._key
                else ""
            )
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(stamped, ensure_ascii=False) + "\n")
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            self._seq += 1
            self._last = digest
            return stamped


__all__ = ["Ledger"]
