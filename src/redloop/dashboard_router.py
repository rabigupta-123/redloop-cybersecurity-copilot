"""
RedLoop Multi-Page Console Navigator.
Run with: streamlit run src/redloop/dashboard_router.py
"""

import streamlit as st

st.set_page_config(
    page_title="RedLoop Cyber Security Console",
    page_icon="🛡️",
    layout="wide",
)

st.sidebar.title("🛡️ RedLoop Console")
nav_items = ["Overview", "Performance Dashboard", "Self-Learning Chat"]
selected = st.sidebar.radio("Navigate", nav_items)

if selected == "Overview":
    import redloop.overview_enhanced
elif selected == "Performance Dashboard":
    import redloop.dashboard_performance
elif selected == "Self-Learning Chat":
    import importlib.util
    from pathlib import Path

    chat_path = Path(__file__).resolve().parent.parent.parent / "self-learning-agent" / "dashboard" / "chat_self_learning.py"
    if chat_path.exists():
        spec = importlib.util.spec_from_file_location("chat_self_learning", chat_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    else:
        st.info("Chat dashboard at self-learning-agent/dashboard/chat_self_learning.py")
