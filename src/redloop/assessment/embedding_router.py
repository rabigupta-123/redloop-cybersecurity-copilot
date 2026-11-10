"""Embedding-based Intent Classifier for REDLOOP Orchestrator (Phase G.2).

Provides local sentence-transformer intent classification as a second-stage tiebreaker
before falling back to GENERAL_CHAT.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Tuple

import numpy as np

logger = logging.getLogger(__name__)

_DEFAULT_TRAIN_PATH = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "fixtures" / "eval" / "intent_train_v2.json"
_WORKSPACE_MODEL_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "models" / "all-MiniLM-L6-v2"
_CENTROIDS_CACHE_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "models" / "intent_centroids.npz"
_EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"


class EmbeddingIntentClassifier:
    """Local, offline sentence-transformers intent classifier.

    Computes semantic similarity against labeled cybersecurity intent clusters.
    """

    _instance: EmbeddingIntentClassifier | None = None

    def __init__(
        self,
        train_path: Path | str | None = None,
        model_name: str = _EMBEDDING_MODEL_NAME,
        min_confidence: float = 0.50,
    ) -> None:
        self.train_path = Path(train_path or _DEFAULT_TRAIN_PATH)
        self.model_name = model_name
        self.min_confidence = min_confidence
        self.model = None
        self.intent_labels: list[str] = []
        self.centroids: np.ndarray | None = None  # shape: (num_classes, embedding_dim)
        self.train_embeddings: np.ndarray | None = None
        self.train_intents: list[str] = []
        self._is_initialized = False
        self._initialize()

    @classmethod
    def get_instance(cls) -> EmbeddingIntentClassifier:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _initialize(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer
            model_target = str(_WORKSPACE_MODEL_PATH) if _WORKSPACE_MODEL_PATH.exists() else self.model_name
            try:
                self.model = SentenceTransformer(model_target, local_files_only=True)
            except Exception:
                self.model = SentenceTransformer(model_target)
        except Exception as e:
            logger.warning(f"Failed to load sentence_transformers ({e}). Embedding intent routing disabled.")
            self._is_initialized = False
            return

        if not self.train_path.exists():
            logger.warning(f"Training dataset not found at {self.train_path}")
            self._is_initialized = False
            return

        # Check if precomputed centroids and embeddings cache exists
        if _CENTROIDS_CACHE_PATH.exists():
            try:
                cached = np.load(_CENTROIDS_CACHE_PATH, allow_pickle=True)
                self.centroids = cached["centroids"]
                self.train_embeddings = cached["train_embeddings"]
                self.intent_labels = list(cached["intent_labels"])
                self.train_intents = list(cached["train_intents"])
                self._is_initialized = True
                logger.info(f"Loaded precomputed intent centroids ({len(self.intent_labels)} classes) from {_CENTROIDS_CACHE_PATH}.")
                return
            except Exception:
                pass

        with open(self.train_path, "r", encoding="utf-8") as f:
            train_data = json.load(f)

        prompts = [d["prompt"] for d in train_data]
        self.train_intents = [d["expected_intent"] for d in train_data]

        # Compute embeddings for all training examples
        embeddings = self.model.encode(prompts, convert_to_numpy=True, normalize_embeddings=True)
        self.train_embeddings = embeddings

        # Compute normalized centroid per class
        class_to_embs: dict[str, list[np.ndarray]] = {}
        for intent, emb in zip(self.train_intents, embeddings):
            class_to_embs.setdefault(intent, []).append(emb)

        self.intent_labels = sorted(class_to_embs.keys())
        centroid_list = []
        for label in self.intent_labels:
            class_matrix = np.array(class_to_embs[label])
            c = np.mean(class_matrix, axis=0)
            norm = np.linalg.norm(c)
            if norm > 0:
                c = c / norm
            centroid_list.append(c)

        self.centroids = np.array(centroid_list)
        self._is_initialized = True

        # Save cache for instant subsequent loading
        try:
            _CENTROIDS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            np.savez_compressed(
                _CENTROIDS_CACHE_PATH,
                centroids=self.centroids,
                train_embeddings=self.train_embeddings,
                intent_labels=np.array(self.intent_labels),
                train_intents=np.array(self.train_intents),
            )
        except Exception:
            pass
        logger.info(f"Initialized EmbeddingIntentClassifier with {len(self.intent_labels)} classes and {len(prompts)} exemplars.")

    def classify(self, prompt: str) -> tuple[str, float]:
        """Classifies prompt returning (predicted_intent, confidence_score).

        If confidence is below min_confidence, returns ('GENERAL_CHAT', confidence).
        """
        if not self._is_initialized or self.model is None or self.centroids is None:
            return "GENERAL_CHAT", 0.0

        p_emb = self.model.encode([prompt], convert_to_numpy=True, normalize_embeddings=True)[0]

        # 1. Cosine similarity against class centroids
        sims = np.dot(self.centroids, p_emb)
        best_idx = int(np.argmax(sims))
        best_score = float(sims[best_idx])
        predicted_class = self.intent_labels[best_idx]

        # 2. Nearest exemplar similarity for precise match boost
        if self.train_embeddings is not None:
            sample_sims = np.dot(self.train_embeddings, p_emb)
            top_sample_idx = int(np.argmax(sample_sims))
            top_sample_score = float(sample_sims[top_sample_idx])
            top_sample_intent = self.train_intents[top_sample_idx]

            # If top exemplar is very high similarity (>=0.75), trust top exemplar's intent
            if top_sample_score >= 0.75:
                return str(top_sample_intent), float(top_sample_score)

        if best_score < self.min_confidence:
            return "GENERAL_CHAT", float(best_score)

        return str(predicted_class), float(best_score)

