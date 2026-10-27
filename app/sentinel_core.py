"""
CloudSentinel-MCP | PS 9 Core Integrity Engine
"""
import json
import hashlib
import sqlite3
from datetime import datetime, timezone, timedelta

def verify_ledger_db(db_file):
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM windows ORDER BY window_id ASC")
    windows = c.fetchall()
    
    c.execute("SELECT * FROM checkpoints")
    checkpoints = {row["window_id"]: dict(row) for row in c.fetchall()}
    conn.close()

    if not windows:
        return {"valid": True, "status": "intact", "message": "No windows found.", "tampered_windows": [], "missing_windows": []}

    results = {
        "valid": True,
        "status": "intact",
        "total_windows": len(windows),
        "tampered_windows": [],
        "missing_windows": [],
        "message": "All windows verified successfully against checkpoints. Status: INTACT."
    }

    expected_id = windows[0]["window_id"]
    for w in windows:
        if w["window_id"] != expected_id:
            while expected_id < w["window_id"]:
                results["valid"] = False
                results["missing_windows"].append(expected_id)
                expected_id += 1
        expected_id = w["window_id"] + 1

    for i in range(len(windows)):
        w = windows[i]
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row
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
            results["tampered_windows"].append({
                "window_id": w["window_id"],
                "reason": tamper_reason,
                "first_detection": detect_ts,
                "anchor_timestamp": w["anchor_timestamp"]
            })

    if results["missing_windows"]:
        results["status"] = "missing"
        results["valid"] = False
        results["message"] = f"Integrity check failed: Missing windows detected: {results['missing_windows']}"
    elif results["tampered_windows"]:
        results["status"] = "tampered"
        results["valid"] = False
        results["message"] = f"Integrity check failed: Tampered windows detected: {[t['window_id'] for t in results['tampered_windows']]}"

    return results
