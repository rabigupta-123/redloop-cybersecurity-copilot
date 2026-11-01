# Optional Self-Learning Service Prototype

This package is separate from RedLoop's primary CLI and FastAPI dashboard. It
is an optional local-development prototype, not a production autonomous
security agent or a replacement for scope-checked RedLoop workflows.

## Implemented behavior

- Local SQLAlchemy storage for experiences, feedback, errors, and generated
  training examples.
- Optional LLM-backed answers when `LLM_API_KEY` is configured.
- Offline experience retrieval using Jaccard overlap of normalized words.
  This is lexical matching, not semantic/vector search.
- A local FastAPI API and Streamlit UI. The API is intended to bind to
  `127.0.0.1`; do not expose it publicly without a separate security review.
- Synthetic LLM responses are available only to automated tests when
  `REDLOOP_ENABLE_TEST_LLM_STUB=1` is set by the test fixture.
- The optional multi-agent path sends role-based prompts to the same configured
  model; it does not run independent agents or provide independent consensus.

## Not implemented or not independently verified

- The fine-tuning endpoint returns HTTP 501. No model training backend is
  implemented, and the service does not change model weights.
- This service does not receive provider token-usage metadata. Its token usage
  is unavailable; the primary RedLoop chat ledger is separate.
- Verification is an LLM self-critique, not an independent proof or security
  validation. Reported confidence is heuristic and should not be treated as a
  calibrated probability.
- CTF file triage passes uploaded bytes to RedLoop's bounded local analyzer.
  It does not execute samples or contact external targets.
- Feedback storage does not automatically establish that an answer is correct.
- Generated training examples are not objectively quality-scored. The
  fine-tuning endpoint is disabled, so they are not used to train a model.

## Local development

Install the optional dependencies from the repository root:

```powershell
pip install -e ".[learning-service,streamlit-dashboard]"
```

From the `self-learning-agent` directory, run the API on loopback:

```powershell
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

The standalone Streamlit UI expects the API at
`http://localhost:8000/api/v1`:

```powershell
streamlit run dashboard/chat_self_learning.py
```

Run its tests from the repository root:

```powershell
pytest self-learning-agent/tests
```
