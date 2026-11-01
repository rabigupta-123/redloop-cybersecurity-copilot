import os
import sys
from pathlib import Path
import pytest
from datetime import datetime
from types import SimpleNamespace

# Add self-learning-agent directory to sys.path
AGENT_ROOT = Path(__file__).resolve().parent.parent
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from config.settings import Settings, get_settings
from database.connection import Base, SessionLocal, engine, init_db
from database.models import AgentStats, ErrorExample, Experience, FineTuneJob, TrainingExample
from database.repositories import (
    agent_stats_repo,
    error_repo,
    experience_repo,
    finetune_job_repo,
    training_example_repo,
)
from memory.error_store import error_store
from memory.experience_store import experience_store
from memory.retrieval import retrieval_engine
from memory.vector_store import VectorStore
from agent.self_learning_agent import SelfLearningAgent
from learning.data_generator import DataGenerator
from learning.finetune import FineTuningPipeline
from fastapi.testclient import TestClient
from api.main import app


@pytest.fixture(autouse=True)
def enable_offline_llm_stub_for_tests(monkeypatch):
    monkeypatch.setenv("REDLOOP_ENABLE_TEST_LLM_STUB", "1")


@pytest.fixture(autouse=True)
def setup_test_db():
    init_db()
    yield


@pytest.mark.asyncio
async def test_learning_llm_fails_closed_without_provider_configuration(monkeypatch):
    from utils.helpers import LLMClient

    monkeypatch.delenv("REDLOOP_ENABLE_TEST_LLM_STUB", raising=False)
    monkeypatch.setattr(
        "utils.helpers.get_settings",
        lambda: SimpleNamespace(
            LLM_API_KEY="",
            LLM_BASE_URL="https://invalid.example",
            LLM_MODEL="test-model",
        ),
    )
    llm = LLMClient()

    with pytest.raises(RuntimeError, match="LLM_API_KEY is not configured"):
        await llm.generate("system", "sensitive prompt")


@pytest.mark.asyncio
async def test_verification_failure_is_not_reported_as_passed():
    from agent.verification import VerificationEngine

    class FailedLLM:
        async def generate(self, **_kwargs):
            raise RuntimeError("provider error contains private details")

    result = await VerificationEngine(FailedLLM()).verify("answer", "problem")

    assert result["passed"] is False
    assert result["status"] == "unavailable"
    assert result["error"] == "RuntimeError"
    assert result["confidence"] == 0.0
    assert "private details" not in str(result)


@pytest.mark.asyncio
async def test_verification_does_not_treat_pass_mentioned_in_failure_as_success():
    from agent.verification import VerificationEngine

    class FailingCritiqueLLM:
        async def generate(self, **_kwargs):
            return "FAIL\nThe answer does not PASS the verification."

    result = await VerificationEngine(FailingCritiqueLLM()).verify("answer", "problem")

    assert result["passed"] is False


def test_settings_and_prompts():
    settings = get_settings()
    assert settings.APP_NAME == "Self-Learning Cyber Agent"
    assert settings.MAX_TOKENS >= 1024
    from config.prompts import SELF_LEARNING_SYSTEM_PROMPT, EFFICIENCY_SYSTEM_PROMPT
    assert "SELF-LEARNING AI" in SELF_LEARNING_SYSTEM_PROMPT
    assert "cybersecurity" in EFFICIENCY_SYSTEM_PROMPT


def test_database_repositories():
    # 1. Experience Repo
    exp = experience_repo.create(
        problem_type="crypto",
        tags=["xor", "caesar"],
        pattern="Single-byte XOR with known plaintext",
        approach="Brute force all 256 keys and inspect flag prefix",
        example_prompt="Ciphertext hex: 1b3737...",
        confidence=0.95,
    )
    assert exp.id is not None
    assert exp.problem_type == "crypto"
    experience_repo.increment_success(exp.id)
    updated = experience_repo.get_by_id(exp.id)
    assert updated.success_count == 2

    # 2. Error Repo
    err = error_repo.create(
        problem="Web challenge with JWT",
        wrong_answer="Assumed HS256 without verification",
        correct_answer="Checked none algorithm flaw",
        error_category="web",
        learned_lesson="Always verify algorithm header before verifying HMAC signature",
    )
    assert err.id is not None
    error_repo.increment_occurrence(err.id)
    err_updated = error_repo.get_by_id(err.id)
    assert err_updated.occurrence_count == 2
    error_repo.mark_fixed(err.id)
    fixed_err = error_repo.get_by_id(err.id)
    assert fixed_err.is_fixed is True

    # 3. Agent Stats Repo
    stat = agent_stats_repo.record_interaction(
        correct=True,
        confidence=92.5,
        tokens=350,
        response_time=45.2,
    )
    assert stat.id is not None
    assert stat.success_rate == 1.0


def test_vector_store_cosine_fallback():
    vs = VectorStore(collection_name="test_experiences")
    v1 = [1.0, 0.0, 0.0]
    v2 = [0.9, 0.1, 0.0]
    v3 = [0.0, 1.0, 0.0]

    vs.add(
        ids=["doc1", "doc2", "doc3"],
        embeddings=[v1, v2, v3],
        documents=["doc1 content", "doc2 content", "doc3 content"],
        metadatas=[{"type": "crypto"}, {"type": "crypto"}, {"type": "pwn"}],
    )

    query_res = vs.query(query_embeddings=[v1], n_results=2)
    assert len(query_res["ids"][0]) == 2
    # doc1 should have smallest distance to v1
    assert query_res["ids"][0][0] == "doc1"


def test_vector_store_does_not_return_entries_without_embeddings(monkeypatch):
    def no_chroma(_name):
        raise ImportError("Chroma disabled for this test")

    monkeypatch.setattr("memory.vector_store.import_module", no_chroma)
    vs = VectorStore(collection_name="test_missing_embedding")
    vs.add(ids=["embedded"], embeddings=[[1.0, 0.0]], documents=["actual vector"])
    vs.add(ids=["missing"], documents=["no vector"])

    query_res = vs.query(query_embeddings=[[1.0, 0.0]])

    assert query_res["ids"] == [["embedded"]]


@pytest.mark.asyncio
async def test_experience_and_error_stores():
    # Store experience
    exp = await experience_store.add(
        problem_type="pwn",
        tags=["bof", "ret2win"],
        pattern="Buffer overflow overwrite instruction pointer",
        approach="Compute cyclic pattern offset and redirect EIP to win()",
        example_prompt="Find the buffer offset for vuln binary",
        confidence=0.88,
    )
    assert exp.id is not None
    await experience_store.update_confidence(exp.id, 0.98)
    all_exps = await experience_store.get_all()
    assert any(e.id == exp.id for e in all_exps)
    unscored = await experience_store.add(
        problem_type="general",
        tags=[],
        pattern="unreviewed",
        approach="unverified feedback",
        example_prompt="not reviewed",
    )
    assert unscored.confidence == 0.0

    # Store error
    err = await error_store.add(
        problem="Reverse engineering stripped binary",
        wrong_answer="Gave up on main function",
        correct_answer="Trace __libc_start_main first argument",
        error_category="rev",
        lesson="In stripped x86-64 binaries, entry point registers point to main via __libc_start_main",
    )
    assert err.id is not None
    recent_errors = await error_store.get_recent_unfixed(days=30)
    assert any(e.id == err.id for e in recent_errors)


def test_offline_retrieval_ranks_lexical_matches(monkeypatch):
    from memory.retrieval import RetrievalEngine

    exact = SimpleNamespace(
        id=2,
        problem_type="pwn",
        tags=["buffer", "overflow"],
        example_prompt="Find the buffer offset",
        pattern="Buffer overflow offset",
        approach="Use a cyclic pattern to calculate the offset",
    )
    unrelated = SimpleNamespace(
        id=1,
        problem_type="crypto",
        tags=["rsa"],
        example_prompt="Decode encrypted text",
        pattern="RSA key recovery",
        approach="Analyze modulus and exponents",
    )
    monkeypatch.setattr(
        "memory.retrieval.experience_repo.get_all",
        lambda: [unrelated, exact],
    )

    results = RetrievalEngine().retrieve_similar(
        "Find the buffer overflow offset", top_k=1
    )

    assert [item["experience"].id for item in results] == [2]
    assert results[0]["similarity"] > 0


@pytest.mark.asyncio
async def test_self_learning_agent_solve_and_feedback():
    agent = SelfLearningAgent(mode="crypto")

    # 1. Solve query
    res = await agent.solve("Analyze ciphertext: 6368616c6c656e6765")
    assert res["success"] is True
    assert "answer" in res
    assert res["confidence"] > 0

    # 2. Learn from positive feedback
    learn_pos = await agent.learn_from_feedback(
        problem="Analyze hex string 6368616c6c656e6765",
        answer="The decoded string is 'challenge'",
        feedback="Correct, excellent analysis!",
    )
    assert learn_pos.get("stored") is True
    assert "experience_id" in learn_pos

    # 3. Learn from negative feedback (correction)
    learn_neg = await agent.learn_from_feedback(
        problem="Analyze custom rot cipher",
        answer="Guessed rot13",
        feedback="Wrong answer: was rot5, not rot13",
    )
    assert learn_neg.get("logged") is True
    assert "error_id" in learn_neg


@pytest.mark.asyncio
async def test_data_generator_and_finetune():
    generator = DataGenerator()
    positives = await generator.generate_from_experiences()
    assert isinstance(positives, list)

    negatives = await generator.generate_from_errors()
    assert isinstance(negatives, list)

    saved_count = await generator.save_to_db(positives + negatives)
    assert saved_count >= 0

    # The repository has no actual fine-tuning backend.
    pipeline = FineTuningPipeline()
    with pytest.raises(RuntimeError, match="no training backend is implemented"):
        await pipeline.create_finetune_job()


def test_api_endpoints():
    client = TestClient(app)

    # 1. Health check
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"

    # 2. Root health/chat
    chat_resp = client.post("/chat", json={"message": "What is an XSS vulnerability?", "mode": "web"})
    assert chat_resp.status_code == 200
    assert "answer" in chat_resp.json()

    # 3. Stats endpoint
    stats_resp = client.get("/stats")
    assert stats_resp.status_code == 200
    assert "stats" in stats_resp.json()

    # 4. Experiences endpoint
    exp_resp = client.get("/experiences")
    assert exp_resp.status_code == 200
    assert "experiences" in exp_resp.json()

    # 5. Generate training data endpoint
    gen_resp = client.post("/generate-training-data")
    assert gen_resp.status_code == 200
    assert "generated" in gen_resp.json()

    finetune = client.post("/api/v1/finetune")
    assert finetune.status_code == 501
    assert "no training backend is implemented" in finetune.json()["detail"]


@pytest.mark.asyncio
async def test_ctf_tool():
    from services.learning_service.ctf_tool import CTFTool

    tool = CTFTool()

    async def capture_orchestrator(filename, content):
        assert filename == "sample.bin"
        assert content == b"sample"
        return SimpleNamespace(flags=[], reports=[])

    tool._run_orchestrator = capture_orchestrator
    triage = await tool.analyze_file_stream(b"sample", "../../sample.bin")
    assert triage["success"] is True
    assert triage["result"]["filename"] == "sample.bin"

    # 1. Flag verification
    ver = tool.verify_flag("Here is the secret flag: CTF{mYth0s_s0lv3d_it}")
    assert ver["is_flag"] is True
    assert "CTF{mYth0s_s0lv3d_it}" in ver["flag"]

    # 2. Text challenge - base64
    b64_res = await tool.solve_text_challenge("ZmxhZ3tzM2NyZXRfYjY0fQ==")
    assert b64_res["success"] is True
    assert "flag{s3cret_b64}" in b64_res["result"]["decoded"]

    # 3. Text challenge - hex
    hex_res = await tool.solve_text_challenge("666c61677b6865785f666c61677d")
    assert hex_res["success"] is True
    assert "flag{hex_flag}" in hex_res["result"]["decoded"]

    # 4. Text challenge - XOR
    xor_res = await tool.solve_text_challenge("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    assert xor_res["success"] is True


@pytest.mark.asyncio
async def test_multi_agent_debate():
    from agent.multi_agent import MultiAgentDebate

    debate_engine = MultiAgentDebate()
    res = await debate_engine.debate("How to mitigate blind SQL injection in a legacy PHP backend?")
    assert "debate" in res
    assert len(res["debate"]) >= 2
    assert "final_answer" in res
    assert res["confidence"] == 0.0
    assert "not verified" in res["consensus"].casefold()


@pytest.mark.asyncio
async def test_mythos_streaming_and_feedback():
    agent = SelfLearningAgent(mode="mythos")
    await agent.initialize()

    # 1. Intent detection
    intent1 = agent.detect_intent("Please decrypt this XOR cipher")
    assert intent1 == "ctf_crypto"

    intent2 = agent.detect_intent("Analyze network trace", files=[{"name": "dump.pcap"}])
    assert intent2 == "ctf_file"

    # 2. Streaming answer
    chunks = []
    async for chunk in agent.stream_answer("What is command injection and how do you remediate it?"):
        chunks.append(chunk)

    assert any(c["type"] == "answer" for c in chunks)
    assert any(c["type"] == "confidence" for c in chunks)

    # 3. Message ID and feedback
    ans_chunk = next(c for c in chunks if c["type"] == "answer")
    assert ans_chunk["data"]

    # Test feedback by message id
    solve_res = await agent.solve("Explain SSRF vulnerability")
    msg_id = solve_res["message_id"]

    fb_res = await agent.learn_from_feedback(msg_id, "correct: clear explanation")
    assert fb_res.get("status") == "learned"

    # Overall stats
    stats = agent.get_overall_stats()
    assert "total_experiences" in stats


def test_learning_service_endpoints():
    from services.learning_service.main import app as service_app

    client = TestClient(service_app)

    # Health check
    h = client.get("/api/v1/health")
    assert h.status_code == 200
    assert h.json()["status"] == "healthy"

    # Stats
    s = client.get("/api/v1/stats")
    assert s.status_code == 200
    assert "stats" in s.json()

    # Experiences
    e = client.get("/api/v1/experiences")
    assert e.status_code == 200
    assert "experiences" in e.json()

    # CTF text analyze
    ctf = client.post("/api/v1/ctf/analyze", json={"source": "text", "content": "ZmxhZ3toZWxsb193b3JsZH0="})
    assert ctf.status_code == 200
    assert ctf.json()["success"] is True

    # Feedback endpoint
    fb = client.post("/api/v1/feedback", json={"message_id": "test_msg_1", "feedback": "correct: very helpful"})
    assert fb.status_code == 200
    assert fb.json()["status"] == "learned"

    # Performance endpoints
    p_sum = client.get("/api/v1/performance/summary")
    assert p_sum.status_code == 200
    assert p_sum.json()["success"] is True
    assert "summary" in p_sum.json()

    p_modes = client.get("/api/v1/performance/modes")
    assert p_modes.status_code == 200
    assert p_modes.json()["success"] is True

    p_trends = client.get("/api/v1/performance/trends")
    assert p_trends.status_code == 200
    assert p_trends.json()["success"] is True

    p_errors = client.get("/api/v1/performance/errors")
    assert p_errors.status_code == 200
    assert p_errors.json()["success"] is True

@pytest.mark.asyncio
async def test_ctf_stream_rejects_missing_file_bytes_without_synthetic_content():
    agent = SelfLearningAgent(mode="general")
    events = [
        event async for event in agent.stream_answer(
            "Analyze this challenge",
            {"uploadedFiles": [{"name": "challenge.bin"}]},
        )
    ]

    assert any(event["type"] == "error" for event in events)
    assert events[-1]["data"] == {"success": False, "verified": False}


def test_performance_metrics_collector():
    from redloop.performance import MetricsCollector, QueryMetric, record_query_metric

    collector = MetricsCollector()
    record_query_metric(
        mode="ctf_crypto",
        latency_ms=120.5,
        confidence=92.0,
        tokens_used=150,
        success=True,
        verified=True,
    )
    record_query_metric(
        mode="ctf_web",
        latency_ms=450.0,
        confidence=40.0,
        tokens_used=300,
        success=False,
        error="Simulation timeout",
    )

    collector.record_learning_event("experience_stored")
    collector.record_learning_event("error_logged")
    collector.record_learning_event("feedback")

    summary = collector.get_summary()
    assert summary["total_queries"] >= 0
    assert summary["experiences_stored"] == 1
    assert summary["errors_logged"] == 1
    assert summary["feedback_received"] == 1

    modes = collector.get_mode_breakdown()
    assert isinstance(modes, dict)

    trends = collector.get_trend_data(hours=12)
    assert len(trends) == 12
