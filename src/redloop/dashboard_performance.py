"""
Professional Performance Dashboard — Latency, Confidence, Learning Rate.
"""

import json
import time
from datetime import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
import streamlit as st

API_BASE = "http://localhost:8080/api/v1"

st.set_page_config(
    page_title="RedLoop Performance",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling
st.markdown(
    """
<style>
body { background-color: #0a0e17; color: #e2e8f0; }
.stApp { background-color: #0a0e17; }

.metric-card {
    background: linear-gradient(135deg, #1a2332 0%, #162029 100%);
    border: 1px solid #2d3748;
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    transition: transform 0.2s;
}
.metric-card:hover {
    transform: translateY(-2px);
    border-color: #4fd1c5;
}
.metric-value {
    font-size: 2rem;
    font-weight: 700;
    color: #fff;
    margin-bottom: 4px;
}
.metric-label {
    font-size: 0.85rem;
    color: #a0aec0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.status-good { color: #48bb78; }
.status-warn { color: #ecc94b; }
.status-bad { color: #fc8181; }

.refresh-indicator {
    display: inline-block;
    width: 8px;
    height: 8px;
    background: #48bb78;
    border-radius: 50%;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
}
</style>
""",
    unsafe_allow_html=True,
)

# Header
col1, col2 = st.columns([3, 1])
with col1:
    st.markdown("# 📊 RedLoop Performance Dashboard")
    st.markdown(
        '<span class="refresh-indicator"></span> <span style="color:#a0aec0;font-size:0.9rem;"> Live telemetry · Auto-refresh active</span>',
        unsafe_allow_html=True,
    )

with col2:
    refresh_interval = st.selectbox("Refresh Interval", ["5s", "10s", "30s", "Manual"], index=0)
    auto_refresh = st.toggle("Auto Refresh", value=True)


@st.cache_data(ttl=5)
def fetch_performance():
    try:
        r = requests.get(f"{API_BASE}/performance/summary", timeout=4)
        return r.json() if r.ok else None
    except Exception:
        return None


@st.cache_data(ttl=10)
def fetch_modes():
    try:
        r = requests.get(f"{API_BASE}/performance/modes", timeout=4)
        return r.json() if r.ok else None
    except Exception:
        return None


@st.cache_data(ttl=10)
def fetch_trends(hours=24):
    try:
        r = requests.get(f"{API_BASE}/performance/trends?hours={hours}", timeout=4)
        return r.json() if r.ok else None
    except Exception:
        return None


@st.cache_data(ttl=10)
def fetch_errors():
    try:
        r = requests.get(f"{API_BASE}/performance/errors", timeout=4)
        return r.json() if r.ok else None
    except Exception:
        return None


perf = fetch_performance()
modes = fetch_modes()
trends = fetch_trends()
errors = fetch_errors()

if not perf or not perf.get("success"):
    st.warning("⚠️ Performance telemetry service not responding on http://localhost:8080. Start the service with:")
    st.code("python -m uvicorn services.learning_service.main:app --port 8080")
else:
    summary = perf["summary"]

    # ===== KPI ROW =====
    st.markdown("### Key Metrics")
    cols = st.columns(5)

    with cols[0]:
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Total Queries</div>
            <div class="metric-value">{summary['total_queries']}</div>
            <div style="font-size:0.8rem;color:#a0aec0;">{summary['uptime_seconds']}s uptime</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with cols[1]:
        sr = summary["success_rate_percent"]
        sr_color = "status-good" if sr >= 80 else ("status-warn" if sr >= 60 else "status-bad")
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Success Rate</div>
            <div class="metric-value"><span class="{sr_color}">{sr}%</span></div>
            <div style="font-size:0.8rem;color:#a0aec0;">{summary['total_successes']} ok / {summary['total_failures']} fail</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with cols[2]:
        lat = summary["avg_latency_ms"]
        lat_color = "status-good" if lat < 2000 else ("status-warn" if lat < 5000 else "status-bad")
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Avg Latency</div>
            <div class="metric-value"><span class="{lat_color}">{lat:.0f}ms</span></div>
            <div style="font-size:0.8rem;color:#a0aec0;">P95: {summary['p95_latency_ms']:.0f}ms</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with cols[3]:
        conf = summary["avg_confidence"]
        conf_color = "status-good" if conf >= 70 else ("status-warn" if conf >= 50 else "status-bad")
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Avg Confidence</div>
            <div class="metric-value"><span class="{conf_color}">{conf:.1f}%</span></div>
            <div style="font-size:0.8rem;color:#a0aec0;">Recent: {summary['recent_avg_confidence']:.1f}%</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    with cols[4]:
        lr = summary["learning_rate"]
        st.markdown(
            f"""
        <div class="metric-card">
            <div class="metric-label">Learning Rate</div>
            <div class="metric-value">{lr}%</div>
            <div style="font-size:0.8rem;color:#a0aec0;">{summary['experiences_stored']} exp · {summary['errors_logged']} err</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    # ===== CHARTS ROW =====
    st.markdown("### Performance Trends (Last 24 Hours)")
    chart_cols = st.columns(2)

    with chart_cols[0]:
        st.markdown("#### 📈 Query Volume & Success Rate")
        if trends and trends.get("trends"):
            df = pd.DataFrame(trends["trends"])
            fig = make_subplots(specs=[[{"secondary_y": True}]])
            fig.add_trace(
                go.Bar(x=df["hour"], y=df["queries"], name="Queries", marker_color="#4fd1c5", opacity=0.7)
            )
            fig.add_trace(
                go.Scatter(x=df["hour"], y=df["success_rate"], name="Success Rate (%)", line=dict(color="#48bb78", width=3)),
                secondary_y=True,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0",
                height=320,
                legend=dict(orientation="h", y=-0.2),
                margin=dict(l=30, r=30, t=20, b=50),
            )
            fig.update_xaxes(gridcolor="#2d3748")
            fig.update_yaxes(gridcolor="#2d3748", title_text="Queries")
            fig.update_yaxes(title_text="Success %", secondary_y=True)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No trend telemetry yet. Run queries through chat to populate.")

    with chart_cols[1]:
        st.markdown("#### ⏱️ Latency Distribution")
        if trends and trends.get("trends"):
            df = pd.DataFrame(trends["trends"])
            fig = go.Figure()
            fig.add_trace(
                go.Scatter(
                    x=df["hour"],
                    y=df["avg_latency_ms"],
                    name="Avg Latency",
                    fill="tozeroy",
                    line=dict(color="#ed8936", width=2),
                    fillcolor="rgba(237, 137, 54, 0.2)",
                )
            )
            fig.add_hline(
                y=2000, line_dash="dash", line_color="#48bb78", annotation_text="Target (<2s)", annotation_position="top right"
            )
            fig.add_hline(
                y=5000, line_dash="dash", line_color="#fc8181", annotation_text="Slow (>5s)", annotation_position="bottom right"
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0",
                height=320,
                margin=dict(l=30, r=30, t=20, b=50),
            )
            fig.update_xaxes(gridcolor="#2d3748")
            fig.update_yaxes(gridcolor="#2d3748", title_text="Latency (ms)")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No latency telemetry recorded yet.")

    # ===== MODE BREAKDOWN TABLE =====
    st.markdown("### 🧩 Performance by Task Mode")
    if modes and modes.get("modes"):
        mode_df = pd.DataFrame(modes["modes"]).T.reset_index()
        mode_df.columns = ["Mode", "Queries", "Avg Latency (ms)", "Avg Confidence", "Success Rate", "Total Tokens"]
        mode_df["Avg Latency (ms)"] = mode_df["Avg Latency (ms)"].apply(lambda x: f"{x:.0f}")
        mode_df["Avg Confidence"] = mode_df["Avg Confidence"].apply(lambda x: f"{x:.1f}%")
        mode_df["Success Rate"] = mode_df["Success Rate"].apply(lambda x: f"{x:.1f}%")
        mode_df["Total Tokens"] = mode_df["Total Tokens"].apply(lambda x: f"{int(x):,}")
        st.dataframe(mode_df, use_container_width=True, hide_index=True)
    else:
        st.info("No per-mode data yet.")

    # ===== RECENT ERRORS =====
    st.markdown("### 🔴 Recent Failures & Anomalies")
    if errors and errors.get("errors"):
        err_df = pd.DataFrame(errors["errors"])
        if not err_df.empty:
            err_df["timestamp"] = pd.to_datetime(err_df["timestamp"]).dt.strftime("%H:%M:%S")
            display_cols = ["timestamp", "mode", "error", "latency_ms", "confidence"]
            avail = [c for c in display_cols if c in err_df.columns]
            st.dataframe(err_df[avail], use_container_width=True, hide_index=True)
    else:
        st.success("✅ Zero active errors. System is fully operational.")

    if auto_refresh and refresh_interval != "Manual":
        time.sleep(int(refresh_interval.replace("s", "")))
        st.rerun()
