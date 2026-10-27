"""
audit.py -- Rail 4, the hoofprints: a hash-chained audit trail.

Regulator question: "What happened, and can you prove it?"

Every gate decision, tool call, phase transition and RACI assignment is
appended with full provenance: who (actor), what (event, inputs, outputs),
when (timestamp) and for which tenant.

A database row history gives you tamper-RESISTANCE at best. A regulator wants
tamper-EVIDENCE: this log is append-only and HASH-CHAINED (each entry commits
to the previous entry's hash), so an after-the-fact edit, a deleted middle
entry or a reorder is detectable by re-walking the chain with ``verify()``.
A regulator can run that check on a laptop with no cloud account.

The walk alone cannot see two attacks: dropping the newest entries, and
re-hashing the whole file after an edit (the hash has no key). Both are
caught against an ANCHOR: ``head()`` returns ``(count, last entry_hash)``;
copy it somewhere the writer cannot change (for example an S3 Object Lock
object, written on a schedule) and pass it to ``verify(anchor=...)``.

Default sink is a local append-only JSONL file. The same append + verify shape
maps onto DynamoDB (one item per entry) with an S3 Object Lock (WORM) export.

AWS covers: CloudTrail log file integrity validation (API calls only) and
S3 Object Lock compliance mode. You still own the content chain (tool
arguments, policy decision, approver) and running the validation. See the
README rail table.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    """Deterministic JSON so the hash is stable across processes/machines."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash_entry(entry: Dict[str, Any]) -> str:
    """Hash of an entry EXCLUDING its own ``entry_hash`` field."""
    payload = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass
class AuditEntry:
    seq: int
    event: str
    actor: str           # who (a user id, or 'pipeline:<id>' / 'sweeper')
    tenant_id: str       # tenant scope of the action
    at: float            # when
    inputs: Dict[str, Any]   # what went in
    outputs: Dict[str, Any]  # what came out
    prev_hash: str
    entry_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "event": self.event,
            "actor": self.actor,
            "tenant_id": self.tenant_id,
            "at": self.at,
            "inputs": self.inputs,
            "outputs": self.outputs,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


class AuditTrail:
    """Append-only, hash-chained audit log.

    Thread-safe. Persists each entry as one JSON line (JSONL) so the file is
    grep-able and the chain is verifiable by re-walking it. ``append`` returns
    the entry hash so callers can correlate.
    """

    def __init__(self, path: Optional[str] = None, now=time.time) -> None:
        self.path = path
        self._now = now
        self._lock = threading.Lock()
        self._entries: List[Dict[str, Any]] = []
        self._last_hash = GENESIS
        if path and os.path.exists(path):
            self._load_existing(path)

    def _load_existing(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                e = json.loads(line)
                self._entries.append(e)
        if self._entries:
            self._last_hash = self._entries[-1]["entry_hash"]

    def append(
        self,
        event: str,
        actor: str,
        tenant_id: str,
        inputs: Optional[Dict[str, Any]] = None,
        outputs: Optional[Dict[str, Any]] = None,
    ) -> str:
        with self._lock:
            seq = len(self._entries)
            entry = AuditEntry(
                seq=seq,
                event=event,
                actor=actor,
                tenant_id=tenant_id,
                at=self._now(),
                inputs=inputs or {},
                outputs=outputs or {},
                prev_hash=self._last_hash,
            ).to_dict()
            entry["entry_hash"] = _hash_entry(entry)
            self._entries.append(entry)
            self._last_hash = entry["entry_hash"]
            if self.path:
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(_canonical(entry) + "\n")
            return entry["entry_hash"]

    # -- read / replay -------------------------------------------------------
    def entries(self, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._entries)
        if tenant_id is not None:
            items = [e for e in items if e["tenant_id"] == tenant_id]
        return items

    def head(self) -> Tuple[int, str]:
        """The anchor to store outside the writer's reach: (count, last hash)."""
        with self._lock:
            return len(self._entries), self._last_hash

    def verify(self, anchor: Optional[Tuple[int, str]] = None) -> "ChainVerification":
        """Re-walk the chain; detect an edit, a deleted entry or a reorder.

        With ``anchor`` (from an earlier ``head()``), also detect dropped
        newest entries and a re-hashed chain."""
        with self._lock:
            items = list(self._entries)
        if anchor is not None:
            count, head_hash = anchor
            if len(items) < count or (
                    items[count - 1].get("entry_hash") if count else GENESIS
            ) != head_hash:
                return ChainVerification(False, min(len(items), count),
                                         f"anchor mismatch at seq {count - 1}")
        # [snippet:rail-4]
        prev = GENESIS
        for i, e in enumerate(items):
            if e.get("prev_hash") != prev:
                return _broken(i, "prev_hash")
            if _hash_entry(e) != e.get("entry_hash"):
                return _broken(i, "entry_hash")
            prev = e["entry_hash"]
        return ChainVerification(True, len(items), "chain intact")
        # [/snippet]


@dataclass
class ChainVerification:
    ok: bool
    checked: int
    detail: str

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.ok


def _broken(seq: int, field_name: str) -> ChainVerification:
    return ChainVerification(False, seq, f"{field_name} mismatch at seq {seq}")
