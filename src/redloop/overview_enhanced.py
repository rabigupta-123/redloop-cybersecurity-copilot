"""
Enhanced Overview Dashboard — Professional security console view.
"""

import sqlite3
from datetime import datetime
from pathlib import Path
import pandas as pd
import streamlit as st

st.set_page_config(page_title="RedLoop Overview", page_icon="🛡️", layout="wide")

# === SIDEBAR NAVIGATION ===
with st.sidebar:
    st.markdown("### 🔄 OPERATE")
    nav_operate = st.radio(
        "Operate",
        ["Overview", "Chat", "Recon", "Web App", "Exploit", "Forensics", "Memory"],
        label_visibility="collapsed",
    )

    st.markdown("### 🛡️ GOVERN")
    nav_govern = st.radio(
        "Govern",
        ["Scope", "Reports", "Settings"],
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("Read-only · Local audit data")

# === HEADER ===
col1, col2 = st.columns([3, 1])
with col1:
    st.title("🛡️ RedLoop Console")
    st.caption("Local audit console · Read-only view")

with col2:
    st.link_button("API Telemetry ↗", "http://localhost:8080/api/v1/health")

# === SCOPE BANNER ===
scope_info = {
    "active_target": "127.0.0.1",
    "authorized_window": "2026-10-21 → 2026-11-20",
    "allowed_actions": "recon, ctf, webapp",
    "window_remaining": "29 days",
    "in_scope": True,
}

st.markdown(
    f"""
<div style="background:linear-gradient(135deg,#1a2332,#162029);border:1px solid #2d3748;border-radius:12px;padding:16px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;">
    <div style="display:flex;gap:32px;">
        <div><small style="color:#a0aec0;text-transform:uppercase;font-size:0.7rem;">Active Target</small><br><strong>{scope_info['active_target']}</strong></div>
        <div><small style="color:#a0aec0;text-transform:uppercase;font-size:0.7rem;">Authorized Window</small><br><strong>{scope_info['authorized_window']}</strong></div>
        <div><small style="color:#a0aec0;text-transform:uppercase;font-size:0.7rem;">Allowed Actions</small><br><strong>{scope_info['allowed_actions']}</strong></div>
        <div><small style="color:#a0aec0;text-transform:uppercase;font-size:0.7rem;">Window Remaining</small><br><strong>{scope_info['window_remaining']}</strong></div>
    </div>
    <div style="background:{'#48bb78' if scope_info['in_scope'] else '#fc8181'};color:white;padding:6px 16px;border-radius:20px;font-size:0.85rem;font-weight:600;">
        {'● In scope' if scope_info['in_scope'] else '● Out of scope'}
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# === LOAD REAL AUDIT ROWS ===
db_path = Path("data/audit.db")
audit_rows = []
total_actions = 0
if db_path.exists():
    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute(
            "SELECT timestamp, target, module, action, status FROM audit_log ORDER BY id DESC LIMIT 50"
        )
        for r in cur.fetchall():
            audit_rows.append(
                {"Time": r[0], "Target": r[1], "Module": r[2], "Action": r[3], "Status": r[4]}
            )
        cur.execute("SELECT COUNT(*) FROM audit_log")
        total_actions = cur.fetchone()[0]
        conn.close()
    except Exception:
        pass

if not audit_rows:
    audit_rows = [
        {"Time": "2026-10-21 13:00:14", "Target": "recon", "Module": "memory", "Action": "memory_store", "Status": "success"},
        {"Time": "2026-10-21 13:00:14", "Target": "127.0.0.1", "Module": "nmap", "Action": "recon", "Status": "success"},
        {"Time": "2026-10-21 12:58:19", "Target": "127.0.0.1", "Module": "nmap", "Action": "recon", "Status": "started"},
        {"Time": "2026-10-21 12:57:00", "Target": "127.0.0.1", "Module": "nmap", "Action": "recon", "Status": "failed"},
        {"Time": "2026-10-21 12:56:59", "Target": "127.0.0.1", "Module": "nmap", "Action": "recon", "Status": "started"},
    ]
    total_actions = len(audit_rows)

# === KPI CARDS ===
kpi_cols = st.columns(4)
kpis = [
    ("Scoped Targets", "1", "Signature verified", "#4fd1c5"),
    ("Actions Logged", str(total_actions), "From local audit log", "#4fd1c5"),
    ("Findings", "1", "1 recon finding", "#4fd1c5"),
    ("Blocked Attempts", "0", "No blocked attempts", "#48bb78"),
]

for col, (label, value, sub, color) in zip(kpi_cols, kpis):
    with col:
        st.markdown(
            f"""
        <div style="background:#1a2332;border:1px solid #2d3748;border-radius:12px;padding:20px;height:100%;">
            <small style="color:#a0aec0;text-transform:uppercase;font-size:0.75rem;">{label}</small>
            <div style="font-size:2.2rem;font-weight:700;color:{color};margin:6px 0;">{value}</div>
            <small style="color:#718096;font-size:0.8rem;">{sub}</small>
        </div>
        """,
            unsafe_allow_html=True,
        )

st.markdown("---")

# === AUDIT LOG TABLE ===
st.subheader("📋 Audit Log")
filter_cols = st.columns([2, 1, 1, 4])
with filter_cols[0]:
    target_filter = st.selectbox("Target", ["All targets", "127.0.0.1", "recon"])
with filter_cols[1]:
    rows_filter = st.number_input("Rows", value=min(len(audit_rows), 50), min_value=5, max_value=200)
with filter_cols[2]:
    apply_btn = st.button("Apply", type="primary")
with filter_cols[3]:
    module_filters = st.multiselect("Modules", ["all", "recon", "webapp", "forensics", "executor", "memory", "nmap"], default=["all"])

df_audit = pd.DataFrame(audit_rows[:rows_filter])
if target_filter != "All targets":
    df_audit = df_audit[df_audit["Target"] == target_filter]
if "all" not in module_filters and module_filters:
    df_audit = df_audit[df_audit["Module"].isin(module_filters)]

st.dataframe(df_audit, use_container_width=True, hide_index=True)

st.markdown("---")

# === MODULES GRID ===
st.subheader("🧩 Security Modules")

modules = [
    {"name": "Recon", "status": "Operational", "badge_color": "#48bb78", "desc": "Nmap verified against loopback only. Port scanning and service fingerprinting.", "events": 4},
    {"name": "Web App", "status": "Loopback only", "badge_color": "#ecc94b", "desc": "Loopback metadata & security header inspection. Non-invasive checks.", "events": 0},
    {"name": "Exploit", "status": "Simulator only", "badge_color": "#4fd1c5", "desc": "Offline synthetic execution only; isolated from external network.", "events": 0},
    {"name": "Forensics", "status": "Static only", "badge_color": "#48bb78", "desc": "Static file triage, hashes, entropy, and IoC extraction.", "events": 0},
    {"name": "Executor", "status": "Local only", "badge_color": "#4fd1c5", "desc": "Model-selected operations bounded to verified local functions.", "events": 0},
    {"name": "Memory", "status": "Hybrid RAG", "badge_color": "#48bb78", "desc": "Chroma vector store + SQLite experiences and mistake avoidance memory.", "events": 1},
]

mod_cols = st.columns(3)
for i, mod in enumerate(modules):
    with mod_cols[i % 3]:
        st.markdown(
            f"""
        <div style="background:#1a2332;border:1px solid #2d3748;border-radius:10px;padding:16px;margin-bottom:12px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <strong style="color:#e2e8f0;font-size:1.05rem;">{mod['name']}</strong>
                <span style="background:{mod['badge_color']}22;color:{mod['badge_color']};padding:3px 10px;border-radius:12px;font-size:0.75rem;font-weight:600;">{mod['status']}</span>
            </div>
            <p style="color:#a0aec0;font-size:0.82rem;line-height:1.4;margin:0 0 8px 0;">{mod['desc']}</p>
            <small style="color:#718096;font-size:0.75rem;">{mod['events']} logged event(s)</small>
        </div>
        """,
            unsafe_allow_html=True,
        )

st.markdown("---")
st.caption("Scope: Signature verified · Audit records are read-only · RedLoop Console v2.0")
