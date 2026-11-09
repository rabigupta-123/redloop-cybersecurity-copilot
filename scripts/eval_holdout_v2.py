import json
import time
from pathlib import Path
from redloop.assessment.orchestrator import TaskOrchestrator
from redloop.assessment.metrics import (
    classification_metrics,
    wilson_score_interval,
    expected_calibration_error,
    calculate_brier_score,
    percentile_latencies,
)

v2_path = Path("tests/fixtures/eval/intent_holdout_v2.json")
with open(v2_path, encoding="utf-8") as f:
    data = json.load(f)

orch = TaskOrchestrator()
y_true = []
y_pred = []
probs = []
outcomes = []
latencies = []

print(f"Evaluating {len(data)} prompts in intent_holdout_v2.json...")
for item in data:
    p = item["prompt"]
    expected = item["expected_intent"]
    t0 = time.perf_counter()
    res = orch.parse_intent(p)
    dt = (time.perf_counter() - t0) * 1000.0
    latencies.append(dt)
    pred = res.get("intent", "GENERAL_CHAT")
    conf = float(res.get("confidence", 0.5))
    y_true.append(expected)
    y_pred.append(pred)
    probs.append(conf)
    matched = (pred == expected)
    outcomes.append(1 if matched else 0)
    if not matched:
        print(f"  MISMATCH: prompt='{p[:60]}' | expected={expected} | pred={pred}")

correct = sum(outcomes)
total = len(data)
acc = correct / total
w_low, w_high = wilson_score_interval(correct, total)
clf = classification_metrics(y_true, y_pred)
ece = expected_calibration_error(probs, outcomes)
brier = calculate_brier_score(probs, outcomes)
lat = percentile_latencies(latencies)

print("\n--- RESULTS FOR INTENT HOLDOUT V2 (Evaluated Exactly Once) ---")
print(f"Sample size: {total}")
print(f"Correct: {correct}")
print(f"Accuracy: {acc:.4f} (Wilson 95% CI: [{w_low:.4f}, {w_high:.4f}])")
print(f"Macro-F1: {clf['macro_f1']:.4f}")
ece_val = ece.get("score") if isinstance(ece, dict) else float(ece)
print(f"ECE: {ece_val}")
print(f"Brier score: {brier:.4f}")
print(f"Latencies: p50={lat['p50']:.2f}ms, p95={lat['p95']:.2f}ms")

# Save results
out_data = {
    "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "dataset": "intent_holdout_v2.json",
    "sample_size": total,
    "correct": correct,
    "accuracy": acc,
    "ci_95": [w_low, w_high],
    "macro_f1": clf["macro_f1"],
    "ece": ece_val,
    "brier": brier,
    "latencies_ms": lat,
}
with open("artifacts/eval_results_v2.json", "w", encoding="utf-8") as f:
    json.dump(out_data, f, indent=2)
print("Saved artifacts/eval_results_v2.json")
