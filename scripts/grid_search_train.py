"""Grid search embedding threshold 0.30-0.55 ON THE TRAIN SET ONLY."""
import json
import numpy as np
from pathlib import Path
from sentence_transformers import SentenceTransformer

train_path = Path("tests/fixtures/eval/intent_train_v2.json")
with open(train_path, "r", encoding="utf-8") as f:
    train_data = json.load(f)

print(f"Loaded {len(train_data)} training items.")

model_path = Path("data/models/all-MiniLM-L6-v2")
if model_path.exists():
    model = SentenceTransformer(str(model_path), local_files_only=True)
else:
    model = SentenceTransformer("all-MiniLM-L6-v2")

prompts = [d["prompt"] for d in train_data]
intents = [d["expected_intent"] for d in train_data]

print("Encoding training prompts...")
embeddings = model.encode(prompts, convert_to_numpy=True, normalize_embeddings=True)
print("Encoded.")

# 5-fold cross validation on train set
np.random.seed(42)
indices = np.arange(len(prompts))
np.random.shuffle(indices)

folds = np.array_split(indices, 5)

thresholds = [0.30, 0.32, 0.34, 0.36, 0.38, 0.40, 0.42, 0.44, 0.46, 0.48, 0.50, 0.52, 0.55]
results = {}

for thresh in thresholds:
    fold_accuracies = []
    fold_recalls = []
    
    for i, test_idx in enumerate(folds):
        train_idx = np.setdiff1d(indices, test_idx)
        
        train_embs = embeddings[train_idx]
        train_lbls = [intents[idx] for idx in train_idx]
        
        test_embs = embeddings[test_idx]
        test_lbls = [intents[idx] for idx in test_idx]
        
        # Compute centroids on fold training set
        class_embs = {}
        for l, emb in zip(train_lbls, train_embs):
            class_embs.setdefault(l, []).append(emb)
            
        labels = sorted(class_embs.keys())
        centroids = []
        for l in labels:
            c = np.mean(class_embs[l], axis=0)
            norm = np.linalg.norm(c)
            if norm > 0:
                c = c / norm
            centroids.append(c)
        centroids = np.array(centroids)
        
        # Evaluate test fold
        correct = 0
        for emb, true_l in zip(test_embs, test_lbls):
            # Centroid similarity
            sims = np.dot(centroids, emb)
            best_i = int(np.argmax(sims))
            best_score = float(sims[best_i])
            pred_l = labels[best_i]
            
            # Exemplar similarity
            sample_sims = np.dot(train_embs, emb)
            top_s_i = int(np.argmax(sample_sims))
            top_score = float(sample_sims[top_s_i])
            if top_score >= 0.75:
                pred_l = train_lbls[top_s_i]
                best_score = top_score
            elif best_score < thresh:
                pred_l = "GENERAL_CHAT"
                
            if pred_l == true_l:
                correct += 1
                
        fold_accuracies.append(correct / len(test_lbls))
        
    mean_acc = float(np.mean(fold_accuracies))
    std_acc = float(np.std(fold_accuracies))
    results[thresh] = {"mean_accuracy": round(mean_acc, 4), "std": round(std_acc, 4)}
    print(f"Threshold: {thresh:.2f} | 5-Fold CV Accuracy: {mean_acc*100:.2f}% (+/- {std_acc*100:.2f}%)")

best_thresh = max(results.keys(), key=lambda t: results[t]["mean_accuracy"])
print(f"\nOptimal threshold on TRAIN SET: {best_thresh:.2f} (Accuracy: {results[best_thresh]['mean_accuracy']*100:.2f}%)")

with open("artifacts/train_grid_search_results.json", "w", encoding="utf-8") as f:
    json.dump({
        "dataset": "intent_train_v2.json",
        "n_samples": len(train_data),
        "method": "5-fold stratified/shuffled cross-validation",
        "grid": results,
        "optimal_threshold": best_thresh
    }, f, indent=2)
print("Saved artifacts/train_grid_search_results.json")

