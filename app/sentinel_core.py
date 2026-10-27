"""
CloudSentinel-MCP | PS 9 Core Integrity Engine & Independent Checkpoint Verifier
=============================================================================
Security hardened with independent external checkpoint storage (outside SQLite DB)
to protect against administrator database rewriting or tampering.
"""
import json
import hashlib
import sqlite3
import os
from datetime import datetime, timezone, timedelta

def get_external_checkpoint_path(db_file):
    return db_file + ".checkpoints_anchor.json"

def load_external_checkpoints(db_file):
    path = get_external_checkpoint_path(db_file)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
            return {int(k): v for k, v in data.items()}
    except Exception:
        return {}

def save_external_checkpoint(db_file, window_id, checkpoint_data):
    path = get_external_checkpoint_path(db_file)
    checkpoints = load_external_checkpoints(db_file)
    checkpoints[window_id] = checkpoint_data
    try:
        with open(path, "w") as f:
            json.dump({str(k): v for k, v in checkpoints.items()}, f, indent=2)
    except Exception as e:
        print(f"Error saving external checkpoint: {e}")

def verify_ledger_db(db_file):
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM windows ORDER BY window_id ASC")
    windows = c.fetchall()
    
    # Load checkpoints from both DB and independent external storage
    c.execute("SELECT * FROM checkpoints")
    db_checkpoints = {row["window_id"]: dict(row) for row in c.fetchall()}
    conn.close()

    external_checkpoints = load_external_checkpoints(db_file)
    # Merge or prioritize external independent checkpoints
    checkpoints = {**db_checkpoints, **external_checkpoints}

    if not windows:
        return {"valid": True, "status": "intact", "message": "No windows found.", "tampered_windows": [], "missing_windows": []}

    results = {
        "valid": True,
        "status": "intact",
        "total_windows": len(windows),
        "tampered_windows": [],
        "missing_windows": [],
        "message": "All windows verified successfully against independent checkpoints. Status: INTACT."
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

        # Verify against independent checkpoint if anchored
        if w["anchored"] == 1 or w["window_id"] in checkpoints:
            if w["window_id"] not in checkpoints:
                is_tampered = True
                tamper_reason = f"Window #{w['window_id']} missing independent checkpoint verification source."
            else:
                chk = checkpoints[w["window_id"]]
                chk_hash = chk.get("window_hash")
                if chk_hash != w["window_hash"]:
                    is_tampered = True
                    tamper_reason = f"Window #{w['window_id']} checkpoint discrepancy: local window hash does not match independently stored immutable checkpoint."

        if is_tampered:
            results["valid"] = False
            detect_ts = datetime.now(timezone.utc).isoformat()
            results["tampered_windows"].append({
                "window_id": w["window_id"],
                "reason": tamper_reason,
                "first_detection": detect_ts,
                "anchor_timestamp": w["anchor_timestamp"] if "anchor_timestamp" in w.keys() and w["anchor_timestamp"] else "N/A"
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
