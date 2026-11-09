import json
import time
from pathlib import Path
from collections import Counter, defaultdict
from redloop.assessment.orchestrator import TaskOrchestrator
from redloop.assessment.metrics import (
    wilson_score_interval,
    expected_calibration_error,
    calculate_brier_score,
    percentile_latencies,
)

v3_path = Path("tests/fixtures/eval/intent_holdout_v3.json")
with open(v3_path, encoding="utf-8") as f:
    data = json.load(f)

orch = TaskOrchestrator()
y_true = []
y_pred = []
probs = []
outcomes = []
latencies = []
all_intents = sorted({item["expected_intent"] for item in data})

print(f"Evaluating {len(data)} prompts in intent_holdout_v3.json (EVALUATED EXACTLY ONCE)...")
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
        print(f"  MISMATCH: prompt='{p[:65]}' | expected={expected} | pred={pred}")

correct = sum(outcomes)
total = len(data)
acc = correct / total
w_low, w_high = wilson_score_interval(correct, total)

# Confusion Matrix
cm = {actual: {pred: 0 for pred in all_intents} for actual in all_intents}
for t, p in zip(y_true, y_pred):
    if t in cm and p in cm[t]:
        cm[t][p] += 1
    else:
        if t not in cm:
            cm[t] = {}
        cm[t][p] = cm[t].get(p, 0) + 1

# Per-class Precision, Recall, F1
per_class = {}
f1_list = []
for intent in all_intents:
    tp = cm[intent].get(intent, 0)
    fp = sum(cm[other].get(intent, 0) for other in all_intents if other != intent)
    fn = sum(cm[intent].get(other, 0) for other in all_intents if other != intent)
    total_class = tp + fn
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    f1_list.append(f1)
    per_class[intent] = {
        "test_items": total_class,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "statistically_proven": total_class >= 10,
    }

macro_f1 = sum(f1_list) / len(f1_list) if f1_list else 0.0

# Cohen's Kappa
po = acc
pe = sum(
    (sum(cm[actual].values()) / total) * (sum(cm[other].get(actual, 0) for other in all_intents) / total)
    for actual in all_intents
)
kappa = (po - pe) / (1 - pe) if (1 - pe) > 0 else 1.0

# V2 comparison
v2_acc = 1.0000  # post-fix v2 baseline
delta = abs(acc - v2_acc)

ece = expected_calibration_error(probs, outcomes)
ece_val = ece.get("score") if isinstance(ece, dict) else float(ece)
brier = calculate_brier_score(probs, outcomes)
lat = percentile_latencies(latencies)

print("\n--- RESULTS FOR INTENT HOLDOUT V3 (EVALUATED EXACTLY ONCE) ---")
print(f"Total Sample Size: {total}")
print(f"Total Correct: {correct}")
print(f"Accuracy: {acc:.4f} (Wilson 95% CI: [{w_low:.4f}, {w_high:.4f}])")
print(f"Macro-F1: {macro_f1:.4f}")
print(f"Cohen's Kappa: {kappa:.4f}")
print(f"Accuracy Delta (|v3 - v2|): {delta:.4f} ({delta*100:.2f} percentage points)")
print(f"Latencies: p50={lat['p50']:.2f}ms, p95={lat['p95']:.2f}ms")

print("\n--- PER-CLASS METRICS ---")
for intent, m in sorted(per_class.items()):
    status = "OK (>=10 items)" if m["statistically_proven"] else "FLAGGED (<10 items)"
    print(f"  {intent:<30}: n={m['test_items']:<2} | P={m['precision']:.4f} | R={m['recall']:.4f} | F1={m['f1']:.4f} | {status}")

# Save artifacts
results_data = {
    "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "dataset": "intent_holdout_v3.json",
    "sample_size": total,
    "correct": correct,
    "accuracy": round(acc, 4),
    "ci_95": [round(w_low, 4), round(w_high, 4)],
    "macro_f1": round(macro_f1, 4),
    "cohens_kappa": round(kappa, 4),
    "v2_accuracy_baseline": v2_acc,
    "accuracy_delta_from_v2": round(delta, 4),
    "generalization_gap_exceeds_5pts": delta > 0.05,
    "ece": round(ece_val, 4),
    "brier_score": round(brier, 4),
    "latencies_ms": lat,
    "per_class": per_class,
}

with open("artifacts/eval_results_v3.json", "w", encoding="utf-8") as f:
    json.dump(results_data, f, indent=2)

with open("artifacts/confusion_matrix_v3.json", "w", encoding="utf-8") as f:
    json.dump(cm, f, indent=2)

print("\nSaved artifacts/eval_results_v3.json and artifacts/confusion_matrix_v3.json")
