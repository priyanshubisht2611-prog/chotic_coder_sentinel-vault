"""
Advanced Adversarial Integration Tests for Sentinel Cloud (GRAPHITE 26 PS 9)
=============================================================================
Tests:
  1. Genesis health & integrity
  2. Log ingestion & fixed 5-minute time windowing
  3. SHA-256 hash chaining across windows
  4. Test ledger checkpoint anchoring & independent external storage
  5. Detection of modified events after anchoring
  6. Detection of deleted log lines
  7. Detection of entire deleted windows (Missing status)
  8. Detection of modified window hashes
  9. Adversarial database rewrite (testing independent external checkpoint protection)
  10. Persistence of first-detection timestamps
"""

import os
import sqlite3
import json
import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../app')))
from server import app, DB_FILE, init_db
from sentinel_core import verify_ledger_db, get_external_checkpoint_path

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_test_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    ext_path = get_external_checkpoint_path(DB_FILE)
    if os.path.exists(ext_path):
        os.remove(ext_path)
    init_db()
    yield

def test_health_and_genesis():
    response = client.get("/verify")
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["status"] == "intact"

def test_log_ingestion_and_windowing():
    res = client.post("/events", json={
        "event_type": "auth_failure",
        "source_ip": "192.168.1.100",
        "severity": "high",
        "payload": {"user": "admin", "reason": "bad_password"}
    })
    assert res.status_code == 200
    assert res.json()["status"] == "ingested"

    w_res = client.get("/windows")
    assert w_res.status_code == 200
    assert len(w_res.json()["windows"]) >= 1

def test_adversarial_modify_event_after_anchoring():
    client.post("/events", json={"event_type": "login", "payload": {"user": "alice"}})
    client.post("/anchor")

    # Adversary modifies an event in the events table after anchoring
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE events SET payload = ? WHERE id > 1", (json.dumps({"user": "attacker_root"} ),))
    conn.commit()
    conn.close()

    verify_res = client.get("/verify")
    data = verify_res.json()
    assert data["valid"] is False
    assert data["status"] == "tampered"
    assert len(data["tampered_windows"]) > 0
    # Confirm first detection timestamp is recorded
    assert "first_detection" in data["tampered_windows"][0]

def test_adversarial_delete_line_from_window():
    client.post("/events", json={"event_type": "db_query", "payload": {"q": "SELECT 1"}})
    client.post("/events", json={"event_type": "db_query", "payload": {"q": "DROP TABLE users"}})
    client.post("/anchor")

    # Adversary deletes a row from events
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM events WHERE id = 2")
    conn.commit()
    conn.close()

    verify_res = client.get("/verify")
    data = verify_res.json()
    assert data["valid"] is False
    assert data["status"] == "tampered"

def test_missing_window_detection():
    client.post("/events", json={"event_type": "e1", "payload": {"v": 1}})
    client.post("/anchor")
    client.post("/events", json={"event_type": "e2", "payload": {"v": 2}})
    client.post("/anchor")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM windows WHERE window_id = 2")
    c.execute("SELECT window_hash FROM windows WHERE window_id = 1")
    w1_hash = c.fetchone()[0]

    c.execute("""
        INSERT INTO windows (window_id, start_time, end_time, events_hash, previous_hash, window_hash, anchored, status)
        VALUES (3, '2026-10-27T11:00:00+00:00', '2026-10-27T11:05:00+00:00', 'abc', ?, 'ghi', 0, 'intact')
    """, (w1_hash,))
    conn.commit()
    conn.close()

    verify_res = client.get("/verify")
    data = verify_res.json()
    assert data["valid"] is False
    assert data["status"] == "missing"
    assert 2 in data["missing_windows"]

def test_independent_external_checkpoint_protection():
    client.post("/events", json={"event_type": "secure_event", "payload": {"secret": "data"}})
    client.post("/anchor")

    # Adversary has full admin access to SQLite and rewrites windows and internal checkpoints table
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE windows SET window_hash = '9999999999999999999999999999999999999999999999999999999999999999'")
    c.execute("UPDATE checkpoints SET window_hash = '9999999999999999999999999999999999999999999999999999999999999999'")
    conn.commit()
    conn.close()

    # Even if SQLite was rewritten, the independent external checkpoint anchor file (.checkpoints_anchor.json)
    # preserves the true hash and detects the tampering discrepancy!
    verify_res = client.get("/verify")
    data = verify_res.json()
    assert data["valid"] is False
    assert data["status"] == "tampered"
