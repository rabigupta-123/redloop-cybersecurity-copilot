"""Evaluate Holdout v5 EXACTLY ONCE and report metrics, confusion matrix, and per-class stats."""
import json
import math
from collections import defaultdict
from pathlib import Path
from redloop.assessment.orchestrator import TaskOrchestrator

v5_path = Path("tests/fixtures/eval/intent_holdout_v5.json")
with open(v5_path, "r", encoding="utf-8") as f:
    items = json.load(f)

print(f"Loaded {len(items)} items from {v5_path}.")

orchestrator = TaskOrchestrator()

y_true = []
y_pred = []
mismatches = []
predictions = []

for idx, item in enumerate(items, 1):
    prompt = item["prompt"]
    expected = item["expected_intent"]
    parsed = orchestrator.parse_intent(prompt)
    predicted = parsed.get("intent", "GENERAL_CHAT")
    router = parsed.get("router", "regex")
    
    y_true.append(expected)
    y_pred.append(predicted)
    
    is_correct = (expected == predicted)
    predictions.append({
        "id": item["id"],
        "prompt": prompt,
        "expected": expected,
        "predicted": predicted,
        "correct": is_correct,
        "router": router
    })
    
    if not is_correct:
        mismatches.append({
            "id": item["id"],
            "prompt": prompt,
            "expected": expected,
            "predicted": predicted,
            "router": router
        })

n = len(items)
k = sum(1 for p in predictions if p["correct"])
accuracy = k / n

# Wilson 95% CI (z = 1.96)
z = 1.96
p = accuracy
wilson_denom = 1 + (z**2) / n
wilson_center = (p + (z**2) / (2 * n)) / wilson_denom
wilson_margin = (z * math.sqrt((p * (1 - p) / n) + (z**2) / (4 * (n**2)))) / wilson_denom
ci_lower = max(0.0, wilson_center - wilson_margin)
ci_upper = min(1.0, wilson_center + wilson_margin)

# Labels
all_labels = sorted(list(set(y_true) | set(y_pred)))

# Confusion matrix
cm = {l: {l2: 0 for l2 in all_labels} for l in all_labels}
for yt, yp in zip(y_true, y_pred):
    cm[yt][yp] += 1

# Per-class precision, recall, F1
class_metrics = {}
macro_prec_list = []
macro_rec_list = []
macro_f1_list = []

for l in all_labels:
    tp = cm[l][l]
    fp = sum(cm[other][l] for other in all_labels if other != l)
    fn = sum(cm[l][other] for other in all_labels if other != l)
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    
    support = sum(cm[l].values())
    class_metrics[l] = {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "support": support
    }
    macro_prec_list.append(prec)
    macro_rec_list.append(rec)
    macro_f1_list.append(f1)

macro_precision = sum(macro_prec_list) / len(macro_prec_list)
macro_recall = sum(macro_rec_list) / len(macro_rec_list)
macro_f1 = sum(macro_f1_list) / len(macro_f1_list)

# Cohen's Kappa
po = accuracy
pe = 0.0
for l in all_labels:
    actual_count = sum(cm[l].values())
    pred_count = sum(cm[other][l] for other in all_labels)
    pe += (actual_count / n) * (pred_count / n)

kappa = (po - pe) / (1 - pe) if (1 - pe) > 0 else 0.0

# Router stage breakdown
emb_routed = sum(1 for p in predictions if p["router"] == "embedding_second_stage")
emb_correct = sum(1 for p in predictions if p["router"] == "embedding_second_stage" and p["correct"])
regex_routed = sum(1 for p in predictions if p["router"] != "embedding_second_stage")
regex_correct = sum(1 for p in predictions if p["router"] != "embedding_second_stage" and p["correct"])

v4_acc = 0.6127
delta_v4 = accuracy - v4_acc
v3_acc = 0.5539
delta_v3 = accuracy - v3_acc

print(f"\n================ EVALUATION SUMMARY (v5 Holdout - SINGLE RUN) ================")
print(f"Sample Size (n): {n}")
print(f"Correct (k): {k}")
print(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"Wilson 95% CI: [{ci_lower:.4f}, {ci_upper:.4f}] (Lower bound: {ci_lower:.4f})")
print(f"Macro-Precision: {macro_precision:.4f}")
print(f"Macro-Recall: {macro_recall:.4f}")
print(f"Macro-F1: {macro_f1:.4f}")
print(f"Cohen's Kappa: {kappa:.4f}")
print(f"Accuracy Delta vs v4: {delta_v4:+.4f} ({delta_v4*100:+.2f} percentage points)")
print(f"Accuracy Delta vs v3: {delta_v3:+.4f} ({delta_v3*100:+.2f} percentage points)")
print(f"Router Attribution: Embedding={emb_routed} (acc={emb_correct/emb_routed*100:.1f}%), Regex/Fallback={regex_routed} (acc={regex_correct/regex_routed*100:.1f}%)")
print(f"Total Mismatches: {len(mismatches)}")

print(f"\nPer-Class Precision / Recall / F1:")
for l, m in sorted(class_metrics.items()):
    if m['support'] > 0:
        pass_fail = "PASS" if m['recall'] >= 0.60 else "FAIL"
        print(f"  [{pass_fail}] {l:<35} P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f} (n={m['support']})")

results_payload = {
    "evaluation_version": "v5",
    "sample_size": n,
    "correct": k,
    "accuracy": round(accuracy, 4),
    "wilson_ci_95": [round(ci_lower, 4), round(ci_upper, 4)],
    "macro_precision": round(macro_precision, 4),
    "macro_recall": round(macro_recall, 4),
    "macro_f1": round(macro_f1, 4),
    "cohen_kappa": round(kappa, 4),
    "v4_accuracy": v4_acc,
    "delta_vs_v4": round(delta_v4, 4),
    "v3_accuracy": v3_acc,
    "delta_vs_v3": round(delta_v3, 4),
    "router_breakdown": {
        "embedding_count": emb_routed,
        "embedding_correct": emb_correct,
        "regex_count": regex_routed,
        "regex_correct": regex_correct
    },
    "class_metrics": class_metrics,
    "mismatches": mismatches
}

with open("artifacts/eval_results_v5.json", "w", encoding="utf-8") as f:
    json.dump(results_payload, f, indent=2)

with open("artifacts/confusion_matrix_v5.json", "w", encoding="utf-8") as f:
    json.dump(cm, f, indent=2)

print("\nSaved artifacts/eval_results_v5.json and artifacts/confusion_matrix_v5.json")

