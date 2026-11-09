import json
import re
from pathlib import Path

def tokenize(text: str) -> list[str]:
    return re.findall(r"\b\w+\b", text.lower())

def get_ngrams(tokens: list[str], n: int) -> set[tuple[str, ...]]:
    return set(tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1))

# Load all prior datasets
train_path = Path("tests/fixtures/eval/intent_train_v2.json")
v1_path = Path("tests/fixtures/eval/intent_holdout_v1.json")
v2_path = Path("tests/fixtures/eval/intent_holdout_v2.json")

prior_prompts = []
for p in (train_path, v1_path, v2_path):
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)
            prior_prompts.extend(x["prompt"] for x in data)

print(f"Loaded {len(prior_prompts)} existing prompts from train, v1, and v2.")

prior_6grams = set()
for p in prior_prompts:
    toks = tokenize(p)
    prior_6grams.update(get_ngrams(toks, 6))

print(f"Total prior 6-grams: {len(prior_6grams)}")
