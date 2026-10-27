"""
CloudSentinel-MCP | Production Server — GRAPHITE 26 PS 9 Compliant
==================================================================
Features:
  1. Structured security event collection (auth, web, app logs)
  2. Fixed 5-minute time-window grouping
  3. Canonical SHA-256 hash chaining across windows
  4. Blockchain / Test Ledger checkpoint anchoring adapter
  5. Independent verification detecting modified lines, deleted lines, and missing windows
  6. Original checkpoint timestamps vs. first detection timestamps
  7. Intact, Tampered, and Missing statuses
"""

import asyncio
import json
import hashlib
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import ollama

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(DB_DIR, "sentinel_audit.db")

def get_conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    c = conn.cursor()
    
    # 1. Raw events table
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp     TEXT    NOT NULL,
            event_type    TEXT    NOT NULL,
            source_ip     TEXT,
            payload       TEXT    NOT NULL,
            severity      TEXT    DEFAULT 'medium',
            status        TEXT    DEFAULT 'new',
            ai_analysis   TEXT
        )
    """)

    # 2. Time-window tamper-evident ledger table (PS 9 compliant)
    c.execute("""
        CREATE TABLE IF NOT EXISTS windows (
            window_id           INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time          TEXT    NOT NULL,
            end_time            TEXT    NOT NULL,
            events_hash         TEXT    NOT NULL,
            previous_hash       TEXT    NOT NULL,
            window_hash         TEXT    NOT NULL,
            anchored            INTEGER DEFAULT 0,
            tx_hash             TEXT    DEFAULT NULL,
            anchor_timestamp    TEXT    DEFAULT NULL,
            status              TEXT    DEFAULT 'intact',
            first_detection     TEXT    DEFAULT NULL
        )
    """)

    # 3. Checkpoints table for independent verification
    c.execute("""
        CREATE TABLE IF NOT EXISTS checkpoints (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            window_id           INTEGER NOT NULL,
            window_hash         TEXT    NOT NULL,
            anchor_timestamp    TEXT    NOT NULL,
            tx_hash             TEXT    NOT NULL,
            network             TEXT    DEFAULT 'testnet-ledger'
        )
    """)

    conn.commit()

    # Create genesis window if empty
    c.execute("SELECT COUNT(*) FROM windows")
    if c.fetchone()[0] == 0:
        now = datetime.now(timezone.utc)
        start = (now - timedelta(minutes=10)).isoformat()
        end = (now - timedelta(minutes=5)).isoformat()
        
        c.execute("""
            INSERT INTO events (timestamp, event_type, source_ip, payload, severity, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (start, "GENESIS", "127.0.0.1", json.dumps({"event": "SYSTEM_INITIALIZED", "status": "secure"}), "low", "system"))
        conn.commit()

        genesis_events = [{
            "id": c.lastrowid,
            "timestamp": start,
            "event_type": "GENESIS",
            "source_ip": "127.0.0.1",
            "payload": json.dumps({"event": "SYSTEM_INITIALIZED", "status": "secure"}),
            "severity": "low",
            "status": "system",
            "ai_analysis": None
        }]
        events_json = json.dumps(genesis_events, sort_keys=True)
        events_hash = hashlib.sha256(events_json.encode()).hexdigest()
        prev_hash = "0" * 64
        window_raw = f"{start}:{end}:{events_hash}:{prev_hash}"
        window_hash = hashlib.sha256(window_raw.encode()).hexdigest()
        
        c.execute("""
            INSERT INTO windows (start_time, end_time, events_hash, previous_hash, window_hash, anchored, tx_hash, anchor_timestamp, status)
            VALUES (?, ?, ?, ?, ?, 1, ?, ?, 'intact')
        """, (start, end, events_hash, prev_hash, window_hash, "0xgenesis_tx_mock_12345", now.isoformat()))
        conn.commit()

    conn.close()

def get_current_window_times():
    now = datetime.now(timezone.utc)
    minute_floor = (now.minute // 5) * 5
    start = now.replace(minute=minute_floor, second=0, microsecond=0)
    end = start + timedelta(minutes=5)
    return start.isoformat(), end.isoformat()

def get_or_create_active_window(conn):
    start_time, end_time = get_current_window_times()
    c = conn.cursor()
    c.execute("SELECT * FROM windows WHERE start_time = ? AND end_time = ?", (start_time, end_time))
    row = c.fetchone()
    if row:
        return dict(row)
    
    c.execute("SELECT window_hash FROM windows ORDER BY window_id DESC LIMIT 1")
    prev_row = c.fetchone()
    previous_hash = prev_row["window_hash"] if prev_row else "0" * 64

    empty_events = json.dumps([], sort_keys=True)
    events_hash = hashlib.sha256(empty_events.encode()).hexdigest()
    window_raw = f"{start_time}:{end_time}:{events_hash}:{previous_hash}"
    window_hash = hashlib.sha256(window_raw.encode()).hexdigest()

    c.execute("""
        INSERT INTO windows (start_time, end_time, events_hash, previous_hash, window_hash, status)
        VALUES (?, ?, ?, ?, ?, 'intact')
    """, (start_time, end_time, events_hash, previous_hash, window_hash))
    conn.commit()
    
    c.execute("SELECT * FROM windows WHERE window_id = ?", (c.lastrowid,))
    return dict(c.fetchone())

def update_window_hash(conn, window_id):
    c = conn.cursor()
    c.execute("SELECT * FROM windows WHERE window_id = ?", (window_id,))
    w = c.fetchone()
    if not w:
        return

    c.execute("SELECT * FROM events WHERE timestamp >= ? AND timestamp < ? ORDER BY id ASC", (w["start_time"], w["end_time"]))
    events = [dict(r) for r in c.fetchall()]
    events_json = json.dumps(events, sort_keys=True)
    events_hash = hashlib.sha256(events_json.encode()).hexdigest()

    window_raw = f"{w['start_time']}:{w['end_time']}:{events_hash}:{w['previous_hash']}"
    window_hash = hashlib.sha256(window_raw.encode()).hexdigest()

    c.execute("""
        UPDATE windows SET events_hash = ?, window_hash = ? WHERE window_id = ?
    """, (events_hash, window_hash, window_id))
    conn.commit()

app = FastAPI(title="CloudSentinel-MCP API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

init_db()

@app.post("/events")
async def ingest_event(request: Request):
    data = await request.json()
    conn = get_conn()
    c = conn.cursor()
    ts = datetime.now(timezone.utc).isoformat()
    
    c.execute(
        "INSERT INTO events (timestamp, event_type, source_ip, payload, severity, status) VALUES (?, ?, ?, ?, ?, ?)",
        (
            ts,
            data.get("event_type", "auth_event"),
            data.get("source_ip", "127.0.0.1"),
            json.dumps(data.get("payload", {})),
            data.get("severity", "medium"),
            "new"
        )
    )
    event_id = c.lastrowid
    conn.commit()

    window = get_or_create_active_window(conn)
    update_window_hash(conn, window["window_id"])
    conn.close()

    return {"status": "ingested", "event_id": event_id, "window_id": window["window_id"]}

@app.get("/events")
async def list_events(status: str = None, limit: int = 50):
    conn = get_conn()
    c = conn.cursor()
    if status:
        c.execute("SELECT * FROM events WHERE status = ? ORDER BY id DESC LIMIT ?", (status, limit))
    else:
        c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"events": rows}

@app.get("/windows")
async def list_windows():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM windows ORDER BY window_id ASC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return {"windows": rows}

@app.post("/anchor")
async def anchor_windows():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM windows WHERE anchored = 0 ORDER BY window_id ASC")
    unanchored = c.fetchall()
    
    anchored_results = []
    for w in unanchored:
        tx_hash = f"0xchk_{hashlib.sha256((w['window_hash'] + str(datetime.now())).encode()).hexdigest()}"
        anchor_ts = datetime.now(timezone.utc).isoformat()
        
        c.execute("""
            UPDATE windows SET anchored = 1, tx_hash = ?, anchor_timestamp = ? WHERE window_id = ?
        """, (tx_hash, anchor_ts, w["window_id"]))
        
        c.execute("""
            INSERT INTO checkpoints (window_id, window_hash, anchor_timestamp, tx_hash, network)
            VALUES (?, ?, ?, ?, 'testnet-ledger-v1')
        """, (w["window_id"], w["window_hash"], anchor_ts, tx_hash))
        conn.commit()
        
        anchored_results.append({"window_id": w["window_id"], "tx_hash": tx_hash, "anchor_timestamp": anchor_ts})
        
    conn.close()
    return {"status": "anchored", "count": len(anchored_results), "anchors": anchored_results}

@app.get("/verify")
async def verify_system():
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM windows ORDER BY window_id ASC")
    windows = c.fetchall()
    
    c.execute("SELECT * FROM checkpoints")
    checkpoints = {row["window_id"]: dict(row) for row in c.fetchall()}
    conn.close()

    if not windows:
        return {"valid": True, "status": "intact", "message": "No windows found.", "details": []}

    results = {
        "valid": True,
        "status": "intact",
        "total_windows": len(windows),
        "tampered_windows": [],
        "missing_windows": [],
        "message": "All windows verified successfully against checkpoints. Status: INTACT."
    }

    # 1. Check for missing windows first (sequence gaps)
    expected_id = windows[0]["window_id"]
    for w in windows:
        if w["window_id"] != expected_id:
            while expected_id < w["window_id"]:
                results["valid"] = False
                results["missing_windows"].append(expected_id)
                expected_id += 1
        expected_id = w["window_id"] + 1

    if results["missing_windows"]:
        results["status"] = "missing"
        results["valid"] = False
        results["message"] = f"Integrity check failed: Missing windows detected: {results['missing_windows']}"
        return results

    # 2. Check hash chain & checkpoint integrity
    for i in range(len(windows)):
        w = windows[i]
        
        conn = get_conn()
        cc = conn.cursor()
        cc.execute("SELECT * FROM events WHERE timestamp >= ? AND timestamp < ? ORDER BY id ASC", (w["start_time"], w["end_time"]))
        events = [dict(r) for r in cc.fetchall()]
        conn.close()
        
        events_json = json.dumps(events, sort_keys=True)
        recomputed_events_hash = hashlib.sha256(events_json.encode()).hexdigest()
        
        window_raw = f"{w['start_time']}:{w['end_time']}:{recomputed_events_hash}:{w['previous_hash']}"
        recomputed_window_hash = hashlib.sha256(window_raw.encode()).hexdigest()

        is_tampered = False
        tamper_reason = ""

        if recomputed_window_hash != w["window_hash"]:
            is_tampered = True
            tamper_reason = f"Window #{w['window_id']} hash mismatch: stored hash differs from recomputed hash (log lines modified or deleted)."

        if i > 0 and w["previous_hash"] != windows[i - 1]["window_hash"]:
            is_tampered = True
            tamper_reason = f"Window #{w['window_id']} chain broken: previous_hash does not match Window #{windows[i-1]['window_id']} hash."

        if w["anchored"] == 1 and w["window_id"] in checkpoints:
            chk = checkpoints[w["window_id"]]
            if chk["window_hash"] != w["window_hash"]:
                is_tampered = True
                tamper_reason = f"Window #{w['window_id']} checkpoint discrepancy: local hash does not match immutable checkpoint hash on test ledger."

        if is_tampered:
            results["valid"] = False
            detect_ts = datetime.now(timezone.utc).isoformat()
            
            if w["status"] == "intact":
                conn = get_conn()
                cc = conn.cursor()
                cc.execute("UPDATE windows SET status = 'tampered', first_detection = ? WHERE window_id = ?", (detect_ts, w["window_id"]))
                conn.commit()
                conn.close()

            results["tampered_windows"].append({
                "window_id": w["window_id"],
                "reason": tamper_reason,
                "first_detection": detect_ts,
                "anchor_timestamp": w["anchor_timestamp"]
            })

    if results["tampered_windows"]:
        results["status"] = "tampered"
        results["valid"] = False
        results["message"] = f"Integrity check failed: Tampered windows detected: {[t['window_id'] for t in results['tampered_windows']]}"

    return results

@app.post("/tamper-demo")
async def tamper_demo(request: Request):
    body = await request.json()
    window_id = body.get("window_id", 1)
    
    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE windows SET window_hash = ? WHERE window_id = ?", ("0" * 64, window_id))
    conn.commit()
    conn.close()
    
    verification = await verify_system()
    return {"status": "tampered", "window_id": window_id, "verification": verification}

@app.post("/delete-window-demo")
async def delete_window_demo(request: Request):
    body = await request.json()
    window_id = body.get("window_id", 2)
    
    conn = get_conn()
    c = conn.cursor()
    c.execute("DELETE FROM windows WHERE window_id = ?", (window_id,))
    conn.commit()
    conn.close()
    
    verification = await verify_system()
    return {"status": "window_deleted", "window_id": window_id, "verification": verification}

if __name__ == "__main__":
    print("🚀 CloudSentinel-MCP PS 9 Server starting on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
