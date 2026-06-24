"""
checkpoint.py -- where durable pipeline checkpoints live (ComplyKit rail 1).

ComplyKit persists run state in Postgres (`pipeline_runs` rows: status,
phase_log, heartbeat_at, token_usage). This harness defaults to a local
JSON-file store so the demo runs free and offline, and documents a drop-in
DynamoDB adapter for AWS (one item per run; the sweeper and /retry both read it).

Both stores implement the same ``CheckpointStore`` Protocol from pipeline.py:
  load(run_id) -> checkpoint | None
  save(run_id, checkpoint)
  list_runs() -> [checkpoint, ...]      (used by the sweeper)
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List, Optional


class JsonCheckpointStore:
    """Durable checkpoint store backed by a single JSON file.

    Each run_id maps to one checkpoint dict. Writes are atomic (temp file +
    os.replace) so a crash mid-write cannot corrupt the store -- the regulated
    analogue of a transactional DB write.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._write_all({})

    def _read_all(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, "r", encoding="utf-8") as f:
            txt = f.read().strip()
        return json.loads(txt) if txt else {}

    def _write_all(self, data: Dict[str, Any]) -> None:
        tmp = f"{self.path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, self.path)

    def load(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._read_all().get(run_id)

    def save(self, run_id: str, checkpoint: Dict[str, Any]) -> None:
        with self._lock:
            data = self._read_all()
            data[run_id] = checkpoint
            self._write_all(data)

    def list_runs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._read_all().values())


# ---------------------------------------------------------------------------
# AWS adapter (documented; not exercised by the free demo).
#
# DynamoDB table `harness_pipeline_runs` (PK: run_id). One item per run holds
# the same checkpoint dict ComplyKit stores in `pipeline_runs`. The sweeper's
# list_runs() becomes a Query on a GSI keyed by status="in_progress". A
# conditional UpdateItem (`status = :in_progress`) reproduces ComplyKit's
# race-safe `.eq("status","in_progress")` reap guard exactly.
#
#   import boto3
#   class DynamoCheckpointStore:
#       def __init__(self, table="harness_pipeline_runs", region="us-east-1",
#                    profile="voteetech"):
#           sess = boto3.Session(profile_name=profile, region_name=region)
#           self.t = sess.resource("dynamodb").Table(table)
#       def load(self, run_id):
#           r = self.t.get_item(Key={"run_id": run_id})
#           return r.get("Item")
#       def save(self, run_id, ckpt):
#           ckpt = {"run_id": run_id, **ckpt}
#           self.t.put_item(Item=ckpt)              # full-item upsert
#       def list_runs(self):
#           return self.t.query(IndexName="status-index",
#               KeyConditionExpression=Key("status").eq("in_progress"))["Items"]
#
# Step Functions / SQS+Lambda mapping: model each Phase as a Lambda task; the
# Pipeline.run loop becomes a Standard Step Functions state machine (one state
# per phase). should_skip becomes a Choice state reading the DynamoDB
# checkpoint; the EventBridge-scheduled sweeper Lambda enforces the terminal
# state. /retry == start-execution with the existing run_id (skip completed
# states); /rerun == start-execution with a fresh run_id.
# ---------------------------------------------------------------------------
