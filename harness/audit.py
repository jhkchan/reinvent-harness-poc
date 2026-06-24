"""
audit.py -- IMMUTABLE, hash-chained AUDIT TRAIL (ComplyKit rail 2).

This is the open-source distillation of ComplyKit's audit story:
  * `gap_analysis_change_history` rows: action_name / action_label /
    old_value / new_value / changed_by (from the X-Account-Id header) /
    changed_at / record_id (`_record_history`).
  * `pipeline_runs.phase_log` (JSONB array of phase boundary events).
  * `raci_reasoning` JSONB with provenance `source ∈
    (matrix|llm_fallback|legacy_v2|manual)`.

ComplyKit relies on Postgres + RLS for tamper-resistance. For a regulator you
want *tamper-EVIDENCE*: this harness makes the log append-only and HASH-CHAINED
(each entry commits to the previous entry's hash, Merkle/blockchain style), so
any after-the-fact edit, deletion, or reordering is detectable by re-walking
the chain. Every gate decision, tool call, phase transition, and RACI
assignment is appended with full provenance (who / what / when / inputs /
outputs).

Default sink is a local append-only JSONL file. The same append+verify shape
maps onto **DynamoDB** (one item per entry, the chain hash as a range key) with
an **S3 Object Lock (WORM)** periodic export for true immutability -- see
README "AWS mapping".
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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
    actor: str           # who (X-Account-Id analogue, or 'pipeline:<id>'/'sweeper')
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

    def verify(self) -> "ChainVerification":
        """Re-walk the chain; detect any tamper (edit / delete / reorder)."""
        with self._lock:
            items = list(self._entries)
        prev = GENESIS
        for i, e in enumerate(items):
            if e.get("prev_hash") != prev:
                return ChainVerification(False, i, f"prev_hash mismatch at seq {i}")
            recomputed = _hash_entry(e)
            if recomputed != e.get("entry_hash"):
                return ChainVerification(False, i, f"entry_hash mismatch at seq {i}")
            prev = e["entry_hash"]
        return ChainVerification(True, len(items), "chain intact")


@dataclass
class ChainVerification:
    ok: bool
    checked: int
    detail: str

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.ok
