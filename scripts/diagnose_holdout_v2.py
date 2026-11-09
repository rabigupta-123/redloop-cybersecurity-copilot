import json
from collections import defaultdict
from redloop.assessment.orchestrator import TaskOrchestrator

with open("tests/fixtures/eval/intent_holdout_v2.json", encoding="utf-8") as f:
    data = json.load(f)

orch = TaskOrchestrator()
matrix = defaultdict(lambda: defaultdict(int))
all_labels = set()
mismatches = []

for idx, item in enumerate(data):
    p = item["prompt"]
    exp = item["expected_intent"]
    pred = orch.parse_intent(p).get("intent", "GENERAL_CHAT")
    all_labels.add(exp)
    all_labels.add(pred)
    matrix[exp][pred] += 1
    if exp != pred:
        mismatches.append({"idx": idx, "prompt": p, "expected": exp, "predicted": pred})

labels = sorted(list(all_labels))
print("Confusion Matrix (Rows: Actual, Cols: Predicted):\n")
col_w = 12
header = f"{'Actual':<25}" + "".join(f"{l[:10]:>{col_w}}" for l in labels) + f"{'Total':>{col_w}}"
print(header)
print("-" * len(header))
for actual in labels:
    row = f"{actual:<25}"
    total_row = sum(matrix[actual][pred] for pred in labels)
    for pred in labels:
        count = matrix[actual][pred]
        row += f"{count:>{col_w}}"
    row += f"{total_row:>{col_w}}"
    print(row)

print("\nColumn totals:")
col_totals = f"{'Total':<25}" + "".join(f"{sum(matrix[act][p] for act in labels):>{col_w}}" for p in labels)
print(col_totals)

print(f"\nTotal items: {len(data)}, Total mismatches: {len(mismatches)}, Correct: {len(data) - len(mismatches)}")
with open("artifacts/mismatches_v2.json", "w", encoding="utf-8") as f:
    json.dump(mismatches, f, indent=2)

with open("artifacts/confusion_matrix_v2.json", "w", encoding="utf-8") as f:
    json.dump({"labels": labels, "matrix": {act: dict(matrix[act]) for act in labels}}, f, indent=2)
print("Saved artifacts/mismatches_v2.json and artifacts/confusion_matrix_v2.json")

