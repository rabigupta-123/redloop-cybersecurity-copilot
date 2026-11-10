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
            try:
                self.model = SentenceTransformer(self.model_name, local_files_only=True)
            except Exception:
                self.model = SentenceTransformer(self.model_name)
        except Exception as e:
            logger.warning(f"Failed to load sentence_transformers ({e}). Embedding intent routing disabled.")
            self._is_initialized = False
            return

        if not self.train_path.exists():
            logger.warning(f"Training dataset not found at {self.train_path}")
            self._is_initialized = False
            return

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
                return top_sample_intent, top_sample_score

        if best_score < self.min_confidence:
            return "GENERAL_CHAT", best_score

        return predicted_class, best_score

