"""Tests for RAIL 2: immutable, hash-chained audit trail (ComplyKit audit story)."""

import os

from harness.audit import GENESIS, AuditTrail


def test_chain_links_and_verifies(tmp_path):
    a = AuditTrail(path=os.path.join(tmp_path, "audit.jsonl"))
    h0 = a.append("e0", "actor1", "t1", {"in": 1}, {"out": 1})
    h1 = a.append("e1", "actor2", "t1", {"in": 2}, {"out": 2})
    entries = a.entries()
    assert len(entries) == 2
    assert entries[0]["prev_hash"] == GENESIS
    assert entries[1]["prev_hash"] == h0
    assert entries[1]["entry_hash"] == h1
    v = a.verify()
    assert v.ok and v.checked == 2


def test_tamper_breaks_chain(tmp_path):
    a = AuditTrail(path=os.path.join(tmp_path, "audit.jsonl"))
    a.append("e0", "actor1", "t1", {"x": 1}, {"y": 1})
    a.append("e1", "actor2", "t1", {"x": 2}, {"y": 2})
    a.append("e2", "actor3", "t1", {"x": 3}, {"y": 3})
    assert a.verify().ok
    # edit a past entry in place -> hash no longer matches recomputation
    a._entries[1]["outputs"]["y"] = 999
    v = a.verify()
    assert not v.ok
    assert v.checked == 1  # failure detected at seq 1


def test_reorder_breaks_chain(tmp_path):
    a = AuditTrail(path=os.path.join(tmp_path, "audit.jsonl"))
    a.append("e0", "x", "t1")
    a.append("e1", "x", "t1")
    a.append("e2", "x", "t1")
    a._entries[1], a._entries[2] = a._entries[2], a._entries[1]
    assert not a.verify().ok


def test_persisted_jsonl_reloads_and_verifies(tmp_path):
    path = os.path.join(tmp_path, "audit.jsonl")
    a = AuditTrail(path=path)
    a.append("e0", "x", "t1", {"a": 1}, {"b": 2})
    a.append("e1", "y", "t2", {"a": 3}, {"b": 4})
    # fresh load from disk reconstructs the chain
    b = AuditTrail(path=path)
    assert len(b.entries()) == 2
    assert b.verify().ok
    # appending to the reloaded trail continues the chain correctly
    b.append("e2", "z", "t1")
    assert b.verify().ok


def test_tenant_filtering(tmp_path):
    a = AuditTrail(path=os.path.join(tmp_path, "audit.jsonl"))
    a.append("e", "x", "tenant-a")
    a.append("e", "x", "tenant-b")
    a.append("e", "x", "tenant-a")
    assert len(a.entries("tenant-a")) == 2
    assert len(a.entries("tenant-b")) == 1
    # filtering does not break full-chain verification
    assert a.verify().ok


def test_provenance_fields_present(tmp_path):
    a = AuditTrail(path=os.path.join(tmp_path, "audit.jsonl"))
    a.append("raci_assigned", "raci_gate", "t1",
             {"control_area": "capital"}, {"source": "matrix"})
    e = a.entries()[0]
    # who / what / when / inputs / outputs all captured
    for field in ("actor", "event", "at", "inputs", "outputs", "tenant_id"):
        assert field in e
    assert e["actor"] == "raci_gate"
    assert e["inputs"]["control_area"] == "capital"
    assert e["outputs"]["source"] == "matrix"
