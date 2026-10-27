"""
CloudSentinel-MCP | War-Room Dashboard
=======================================
Run: streamlit run dashboard.py
"""

import streamlit as st
import requests
import json

API = "http://localhost:8000"

st.set_page_config(page_title="CloudSentinel-MCP", page_icon="🛡️", layout="wide")

# ── HEADER ──
st.title("🛡️ CloudSentinel-MCP")
st.caption("Autonomous Cloud Security Agent — MCP • Local LLM • Tamper-Evident Ledger")

# ── SIDEBAR ──
st.sidebar.header("⚡ Controls")
auto_refresh = st.sidebar.checkbox("Auto-refresh (5s)", value=False)

# ── LEDGER INTEGRITY ──
st.header("⛓️ Cryptographic Audit Ledger")
col_verify, col_tamper = st.columns(2)

with col_verify:
    if st.button("🔍 Verify Ledger Integrity", use_container_width=True):
        try:
            res = requests.get(f"{API}/verify", timeout=5).json()
            if res["valid"]:
                st.success(f"✅ {res['message']}")
            else:
                st.error(f"🚨 {res['message']}")
        except Exception as e:
            st.error(f"Server connection failed: {e}")

with col_tamper:
    tamper_id = st.number_input("Block ID to tamper", min_value=2, value=2, step=1)
    if st.button("💣 Simulate Tamper Attack", use_container_width=True):
        try:
            res = requests.post(f"{API}/tamper-demo", json={"block_id": tamper_id}, timeout=5).json()
            verification = res["verification"]
            if not verification["valid"]:
                st.error(f"🚨 TAMPERING DETECTED! {verification['message']}")
            else:
                st.warning("Tamper did not break the chain (block may not exist).")
        except Exception as e:
            st.error(f"Failed: {e}")

# ── SECURITY EVENTS ──
st.header("🚨 Live Security Events")
col_all, col_new, col_analyzed = st.columns(3)

try:
    events_res = requests.get(f"{API}/events?limit=50", timeout=5).json()
    events = events_res.get("events", [])

    new_count = sum(1 for e in events if e.get("status") == "new")
    analyzed_count = sum(1 for e in events if e.get("status") == "analyzed")

    col_all.metric("Total Events", len(events))
    col_new.metric("🆕 Pending Review", new_count)
    col_analyzed.metric("🤖 AI Analyzed", analyzed_count)

    for event in events:
        severity = event.get("severity", "unknown")
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

        with st.expander(f"{icon} Event #{event['id']} — {event['event_type']} — {severity.upper()} — [{event['status']}]"):
            st.markdown(f"**Timestamp:** {event['timestamp']}")
            st.markdown(f"**Source IP:** `{event['source_ip']}`")
            st.markdown(f"**Severity:** {severity}")
            st.markdown(f"**Status:** {event['status']}")

            # Show payload
            try:
                payload = json.loads(event.get("payload", "{}"))
                st.json(payload)
            except:
                st.text(event.get("payload", ""))

            # Show existing AI analysis
            if event.get("ai_analysis"):
                st.subheader("🤖 AI SOC Analysis")
                try:
                    analysis = json.loads(event["ai_analysis"])
                    st.json(analysis)
                except:
                    st.markdown(event["ai_analysis"])

            # Button to trigger AI analysis
            if st.button(f"🧠 Analyze Event #{event['id']}", key=f"analyze_{event['id']}"):
                with st.spinner(f"Local LLM analyzing Event #{event['id']}..."):
                    try:
                        res = requests.post(f"{API}/analyze/{event['id']}", timeout=120).json()
                        st.subheader("🤖 AI SOC Analysis Result")
                        try:
                            analysis = json.loads(res.get("analysis", "{}"))
                            st.json(analysis)
                        except:
                            st.markdown(res.get("analysis", "No analysis returned."))
                        st.success("Analysis complete and recorded in ledger!")
                    except Exception as e:
                        st.error(f"Analysis failed: {e}")

except Exception as e:
    st.warning(f"Cannot reach server at {API}: {e}")
    st.info("Start the server first: `python app/server.py`")

# ── LEDGER EXPLORER ──
st.header("📜 Ledger Block Explorer")
try:
    ledger_res = requests.get(f"{API}/ledger?limit=30", timeout=5).json()
    chain = ledger_res.get("chain", [])

    st.caption(f"Showing {len(chain)} most recent blocks (newest first)")

    for block in chain:
        with st.expander(f"Block #{block['id']} — {block['event_type']} — {block['timestamp'][:19]}"):
            st.markdown(f"**Hash:** `{block['hash']}`")
            st.markdown(f"**Previous Hash:** `{block['previous_hash']}`")
            try:
                st.json(json.loads(block["data"]))
            except:
                st.text(block["data"])

except Exception as e:
    st.warning(f"Cannot load ledger: {e}")

# ── AUTO REFRESH ──
if auto_refresh:
    import time
    time.sleep(5)
    st.rerun()
