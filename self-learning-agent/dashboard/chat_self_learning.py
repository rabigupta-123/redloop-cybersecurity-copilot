import json
import requests
import streamlit as st

API_BASE = "http://localhost:8000/api/v1"

st.set_page_config(page_title="Self-Learning Cyber Agent", layout="wide", page_icon="🧠")

if "session_id" not in st.session_state:
    st.session_state.session_id = 1
if "messages" not in st.session_state:
    st.session_state.messages = []

st.title("🧠 Self-Learning Cyber Security Agent")
st.caption("Continuous learning from cybersecurity interactions, mistakes, and explicit user verification.")

col1, col2 = st.columns([3, 1])

with col1:
    mode = st.selectbox("Agent Mode", ["general", "crypto", "web", "pwn", "rev", "forensics", "recon", "vuln"], index=0)

with col2:
    if st.button("🔄 Clear Chat History"):
        st.session_state.messages = []
        st.rerun()

# Display chat history
for idx, message in enumerate(st.session_state.messages):
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if message["role"] == "assistant" and "result" in message:
            res = message["result"]
            verification = res.get("verified")
            if not isinstance(verification, dict) or verification.get("status") == "unavailable":
                verification_label = "Unavailable"
            else:
                verification_label = (
                    "Passed" if verification.get("passed") is True else "Not verified"
                )
            st.caption(
                f"⚡ Confidence: {res.get('confidence', 0)}% | "
                f"Response time: {res.get('response_time_ms', 0):.0f}ms | "
                f"Verification: {verification_label}"
            )

# User input prompt
prompt = st.chat_input("Ask about CTF, security, cryptography, exploit analysis...")

if prompt:
    # Append user prompt
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # Call FastAPI backend
    with st.spinner("Analyzing and retrieving experiences..."):
        try:
            response = requests.post(
                f"{API_BASE}/chat",
                json={"message": prompt, "mode": mode},
                timeout=60,
            )
            result = response.json()
        except Exception as exc:
            result = {
                "answer": f"Error connecting to backend: {exc}",
                "confidence": 0,
                "response_time_ms": 0,
            }

    answer = result.get("answer", "No response generated.")
    confidence = result.get("confidence", 0)

    with st.chat_message("assistant"):
        st.markdown(answer)
        st.info(f"Confidence: {confidence}% | Response time: {result.get('response_time_ms', 0):.0f}ms")

    st.session_state.messages.append({
        "role": "assistant",
        "content": answer,
        "result": result,
        "problem": prompt,
    })

# Feedback on last assistant response
if st.session_state.messages and st.session_state.messages[-1]["role"] == "assistant":
    last_msg = st.session_state.messages[-1]
    last_problem = last_msg.get("problem", "")
    last_answer = last_msg.get("content", "")

    st.divider()
    st.write("**Was this answer helpful and correct?**")
    fb_col1, fb_col2 = st.columns(2)
    with fb_col1:
        if st.button("✅ Correct (Learn this pattern)", key="btn_correct"):
            try:
                requests.post(
                    f"{API_BASE}/feedback",
                    json={
                        "problem": last_problem,
                        "answer": last_answer,
                        "feedback": "Correct answer, well explained",
                    },
                    timeout=10,
                )
                st.success("Stored as a successful experience! The agent will reuse this pattern.")
            except Exception as e:
                st.error(f"Failed to submit feedback: {e}")

    with fb_col2:
        if st.button("❌ Incorrect (Log mistake to avoid)", key="btn_wrong"):
            try:
                requests.post(
                    f"{API_BASE}/feedback",
                    json={
                        "problem": last_problem,
                        "answer": last_answer,
                        "feedback": "Wrong answer, error in reasoning",
                    },
                    timeout=10,
                )
                st.warning("Mistake logged! The agent will avoid repeating this error.")
            except Exception as e:
                st.error(f"Failed to submit feedback: {e}")

# Sidebar Telemetry
st.sidebar.title("📊 Self-Learning Telemetry")
try:
    stats_res = requests.get(f"{API_BASE}/stats", timeout=5)
    if stats_res.ok:
        stats_data = stats_res.json().get("stats", [])
        if stats_data:
            latest = stats_data[0]
            st.sidebar.metric("Success Rate", f"{latest.get('success_rate', 0.0) * 100:.1f}%")
            st.sidebar.metric("Avg Confidence", f"{latest.get('avg_confidence', 0.0):.1f}%")
            st.sidebar.metric("Avg Latency", f"{latest.get('avg_response_time_ms', 0.0):.0f} ms")
except Exception:
    st.sidebar.caption("Backend telemetry offline.")

st.sidebar.divider()
if st.sidebar.button("⚙️ Generate Fine-Tuning Data"):
    try:
        gen_res = requests.post(f"{API_BASE}/generate-training-data", timeout=30)
        st.sidebar.success(f"Generated {gen_res.json().get('generated_examples', 0)} training examples.")
    except Exception as e:
        st.sidebar.error(f"Generation error: {e}")
