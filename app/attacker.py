"""
CloudSentinel-MCP | Attack Simulator
=====================================
Generates realistic security events and sends them to the local server.
Run: python attacker.py --attack <type>

Attack types:
  brute_force    — Simulates SSH brute-force login attempts
  sql_injection  — Simulates SQL injection in HTTP request
  port_scan      — Simulates rapid port scanning
  data_exfil     — Simulates data exfiltration over DNS
  api_abuse      — Simulates API token misuse / credential stuffing
  full_scenario  — Runs all attacks in sequence (best for demo)
"""

import argparse
import json
import random
import time
import requests

SERVER = "http://localhost:8000/events"

FAKE_IPS = [
    "185.220.101.34", "23.129.64.210", "171.25.193.20",
    "45.154.255.147", "194.26.192.64", "103.253.41.98",
    "192.168.1.105", "10.0.0.42"
]

def send_event(event):
    try:
        r = requests.post(SERVER, json=event, timeout=5)
        data = r.json()
        print(f"  ✅ Event ingested → ID #{data.get('event_id', '?')}")
    except Exception as e:
        print(f"  ❌ Failed to send: {e}")

def attack_brute_force(count=5):
    print("\n🔓 Simulating SSH Brute-Force Attack...")
    ip = random.choice(FAKE_IPS)
    usernames = ["root", "admin", "ubuntu", "deploy", "postgres"]
    for i in range(count):
        event = {
            "event_type": "ssh_brute_force",
            "source_ip": ip,
            "severity": "high",
            "payload": {
                "target_port": 22,
                "username": usernames[i % len(usernames)],
                "attempt_number": i + 1,
                "total_attempts_from_ip": count,
                "auth_result": "FAILED",
                "password_hash": hashlib.sha256(f"pass{i}".encode()).hexdigest()[:16]
            }
        }
        send_event(event)
        time.sleep(0.3)

def attack_sql_injection():
    print("\n💉 Simulating SQL Injection Attack...")
    payloads = [
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM admin_users --",
        "1; EXEC xp_cmdshell('net user hacker P@ss123 /add') --"
    ]
    for payload in payloads:
        event = {
            "event_type": "sql_injection",
            "source_ip": random.choice(FAKE_IPS),
            "severity": "critical",
            "payload": {
                "http_method": "POST",
                "endpoint": "/api/v1/login",
                "parameter": "username",
                "injected_value": payload,
                "http_status": 500,
                "response_time_ms": random.randint(2000, 8000),
                "waf_triggered": False
            }
        }
        send_event(event)
        time.sleep(0.3)

def attack_port_scan():
    print("\n🔍 Simulating Port Scan...")
    ip = random.choice(FAKE_IPS)
    scanned_ports = random.sample(range(1, 65535), 20)
    event = {
        "event_type": "port_scan",
        "source_ip": ip,
        "severity": "medium",
        "payload": {
            "scan_type": "SYN",
            "ports_scanned": sorted(scanned_ports),
            "open_ports_found": [22, 80, 443, 3306],
            "scan_duration_seconds": round(random.uniform(0.5, 3.0), 2),
            "os_fingerprint": "Linux 5.x"
        }
    }
    send_event(event)

def attack_data_exfil():
    print("\n📤 Simulating Data Exfiltration via DNS...")
    event = {
        "event_type": "data_exfiltration",
        "source_ip": "10.0.0.42",
        "severity": "critical",
        "payload": {
            "method": "dns_tunneling",
            "dns_queries_per_minute": 847,
            "average_query_length": 189,
            "destination_domain": "exfil.malware-c2.example.com",
            "estimated_data_volume_kb": 2450,
            "encoding": "base64"
        }
    }
    send_event(event)

def attack_api_abuse():
    print("\n🔑 Simulating API Token Abuse...")
    events = [
        {
            "event_type": "api_abuse",
            "source_ip": random.choice(FAKE_IPS),
            "severity": "high",
            "payload": {
                "endpoint": "/api/v1/admin/users",
                "method": "GET",
                "token_prefix": "sk-live-****",
                "requests_per_minute": 342,
                "normal_rpm": 12,
                "geo_anomaly": True,
                "usual_country": "IN",
                "request_country": "RU"
            }
        },
        {
            "event_type": "api_abuse",
            "source_ip": random.choice(FAKE_IPS),
            "severity": "critical",
            "payload": {
                "endpoint": "/api/v1/billing/export",
                "method": "POST",
                "token_prefix": "sk-live-****",
                "data_requested": "full_customer_database",
                "requester_role": "viewer",
                "required_role": "admin",
                "privilege_escalation": True
            }
        }
    ]
    for e in events:
        send_event(e)
        time.sleep(0.3)

def full_scenario():
    print("=" * 60)
    print("🚨 FULL ATTACK SCENARIO — CloudSentinel-MCP Demo")
    print("=" * 60)
    attack_port_scan()
    time.sleep(1)
    attack_brute_force(count=4)
    time.sleep(1)
    attack_sql_injection()
    time.sleep(1)
    attack_api_abuse()
    time.sleep(1)
    attack_data_exfil()
    print("\n" + "=" * 60)
    print("✅ Full attack scenario complete. Check dashboard!")
    print("=" * 60)

import hashlib  # needed in brute_force

ATTACKS = {
    "brute_force": attack_brute_force,
    "sql_injection": attack_sql_injection,
    "port_scan": attack_port_scan,
    "data_exfil": attack_data_exfil,
    "api_abuse": attack_api_abuse,
    "full_scenario": full_scenario
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CloudSentinel-MCP Attack Simulator")
    parser.add_argument("--attack", choices=list(ATTACKS.keys()), default="full_scenario",
                        help="Type of simulated attack (default: full_scenario)")
    args = parser.parse_args()

    print(f"\n🎯 Running attack: {args.attack}")
    ATTACKS[args.attack]()
