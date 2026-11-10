"""Re-score the EXACT SAME Holdout v5 fixture after Phase J fixes.
Report per-class precision, recall, F1, confusion matrix, and gate verifications:
- OSINT_USERNAME recall >= 0.75
- CODING_AND_RESEARCH recall >= 0.70
- GENERAL_CHAT precision reported with delta vs 0.60
"""
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
k = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp)
acc = k / n

# Wilson 95% Confidence Interval (z = 1.96)
z = 1.96
p = acc
denom = 1.0 + (z**2) / n
center = (p + (z**2) / (2 * n)) / denom
margin = (z * math.sqrt((p * (1 - p) / n) + (z**2) / (4 * (n**2)))) / denom
ci_lower = max(0.0, center - margin)
ci_upper = min(1.0, center + margin)

# Per-class metrics
classes = sorted(list(set(y_true)))
class_stats = {}

for c in classes:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp == c)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt != c and yp == c)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == c and yp != c)
    supp = sum(1 for yt in y_true if yt == c)
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    
    class_stats[c] = {
        "support": supp,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4)
    }

macro_prec = sum(s["precision"] for s in class_stats.values()) / len(classes)
macro_rec = sum(s["recall"] for s in class_stats.values()) / len(classes)
macro_f1 = sum(s["f1"] for s in class_stats.values()) / len(classes)

# Confusion Matrix
confusion_matrix = {c1: {c2: 0 for c2 in classes} for c1 in classes}
for yt, yp in zip(y_true, y_pred):
    if yp in confusion_matrix.get(yt, {}):
        confusion_matrix[yt][yp] += 1
    else:
        confusion_matrix[yt][yp] = 1

# Gate Verifications
username_recall = class_stats.get("OSINT_USERNAME", {}).get("recall", 0.0)
coding_recall = class_stats.get("CODING_AND_RESEARCH", {}).get("recall", 0.0)
genchat_prec = class_stats.get("GENERAL_CHAT", {}).get("precision", 0.0)
genchat_delta = genchat_prec - 0.6000

print("\n=================== PHASE J RE-SCORE EVALUATION ===================")
print(f"Total holdout items (n): {n}")
print(f"Correct predictions (k): {k}")
print(f"Accuracy: {acc:.4f} ({acc*100:.2f}%)")
print(f"Wilson 95% CI: [{ci_lower:.4f}, {ci_upper:.4f}]")
print(f"Macro-Precision: {macro_prec:.4f}")
print(f"Macro-Recall: {macro_rec:.4f}")
print(f"Macro-F1: {macro_f1:.4f}")
print(f"\n--- Gate Checks ---")
print(f"Gate J.1 - OSINT_USERNAME Recall: {username_recall:.4f} (Target >= 0.75) -> {'PASSED' if username_recall >= 0.75 else 'FAILED'}")
print(f"Gate J.2 - CODING_AND_RESEARCH Recall: {coding_recall:.4f} (Target >= 0.70) -> {'PASSED' if coding_recall >= 0.70 else 'FAILED'}")
print(f"Gate J.2 - GENERAL_CHAT Precision: {genchat_prec:.4f} (Baseline: 0.6000, Delta: {genchat_delta:+.4f})")
print(f"\nPer-class summary:")
for c, s in class_stats.items():
    print(f"  {c:35} | Supp: {s['support']:2d} | P: {s['precision']:.4f} | R: {s['recall']:.4f} | F1: {s['f1']:.4f}")

out_results = {
    "evaluation_set": "tests/fixtures/eval/intent_holdout_v5.json",
    "phase": "Phase J Re-score",
    "sample_size": n,
    "correct_predictions": k,
    "accuracy": round(acc, 4),
    "wilson_ci_95": [round(ci_lower, 4), round(ci_upper, 4)],
    "macro_precision": round(macro_prec, 4),
    "macro_recall": round(macro_rec, 4),
    "macro_f1": round(macro_f1, 4),
    "gate_verifications": {
        "osint_username_recall": round(username_recall, 4),
        "osint_username_gate_passed": username_recall >= 0.75,
        "coding_and_research_recall": round(coding_recall, 4),
        "coding_and_research_gate_passed": coding_recall >= 0.70,
        "general_chat_precision": round(genchat_prec, 4),
        "general_chat_precision_delta_vs_0_60": round(genchat_delta, 4)
    },
    "per_class": class_stats,
    "mismatches": mismatches
}

with open("artifacts/eval_results_v5_phase_j.json", "w", encoding="utf-8") as f:
    json.dump(out_results, f, indent=2)

with open("artifacts/confusion_matrix_v5_phase_j.json", "w", encoding="utf-8") as f:
    json.dump(confusion_matrix, f, indent=2)

print("\nSaved artifacts/eval_results_v5_phase_j.json and artifacts/confusion_matrix_v5_phase_j.json.")
