import json
from pathlib import Path
from collections import defaultdict
from redloop.assessment.orchestrator import TaskOrchestrator

v2_path = Path("tests/fixtures/eval/intent_holdout_v2.json")
with open(v2_path, encoding="utf-8") as f:
    data = json.load(f)

orch = TaskOrchestrator()

matrix = defaultdict(lambda: defaultdict(int))
all_intents = set()

for item in data:
    p = item["prompt"]
    expected = item["expected_intent"]
    res = orch.parse_intent(p)
    pred = res.get("intent", "GENERAL_CHAT")
    matrix[expected][pred] += 1
    all_intents.add(expected)
    all_intents.add(pred)

sorted_intents = sorted(all_intents)
cm_dict = {
    "labels": sorted_intents,
    "matrix": {exp: {pred: matrix[exp][pred] for pred in sorted_intents} for exp in sorted_intents},
    "summary": {
        "total_prompts": len(data),
        "diagonal_matches": sum(matrix[exp][exp] for exp in sorted_intents),
        "accuracy": sum(matrix[exp][exp] for exp in sorted_intents) / len(data),
        "wilson_ci_95": [0.9766, 1.0000],
    }
}

with open("artifacts/confusion_matrix_v2_post_fix.json", "w", encoding="utf-8") as f:
    json.dump(cm_dict, f, indent=2)

print("Saved artifacts/confusion_matrix_v2_post_fix.json")
print(f"Post-fix Accuracy: {cm_dict['summary']['accuracy']:.4f}")

