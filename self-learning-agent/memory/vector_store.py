"""Vector store supporting ChromaDB with seamless local fallback."""

from __future__ import annotations

import math
import os
from importlib import import_module
from typing import Any, Dict, List, Optional


class VectorStore:
    """Unified Vector Store supporting ChromaDB and in-memory cosine fallback."""

    def __init__(self, collection_name: str = "experiences", persist_dir: str = "./chroma_db"):
        self.collection_name = collection_name
        self.persist_dir = persist_dir
        self.use_chroma = False
        self._collection = None

        try:
            chromadb = import_module("chromadb")
            os.makedirs(persist_dir, exist_ok=True)
            self._client = chromadb.PersistentClient(path=persist_dir)
            self._collection = self._client.get_or_create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            self.use_chroma = True
        except ImportError:
            # Fallback to in-memory cosine similarity store
            self._store: Dict[str, Dict[str, Any]] = {}

    def add(
        self,
        ids: List[str],
        embeddings: Optional[List[List[float]]] = None,
        documents: Optional[List[str]] = None,
        metadatas: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        if self.use_chroma and self._collection is not None:
            self._collection.add(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
            )
            return

        for i, item_id in enumerate(ids):
            emb = embeddings[i] if embeddings and i < len(embeddings) else None
            doc = documents[i] if documents and i < len(documents) else ""
            meta = metadatas[i] if metadatas and i < len(metadatas) else {}
            self._store[item_id] = {
                "embedding": emb,
                "document": doc,
                "metadata": meta,
            }

    def update(
        self,
        ids: List[str],
        embeddings: Optional[List[List[float]]] = None,
        documents: Optional[List[str]] = None,
        metadatas: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        if self.use_chroma and self._collection is not None:
            self._collection.update(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
            )
            return

        for i, item_id in enumerate(ids):
            if item_id in self._store:
                if embeddings and i < len(embeddings):
                    self._store[item_id]["embedding"] = embeddings[i]
                if documents and i < len(documents):
                    self._store[item_id]["document"] = documents[i]
                if metadatas and i < len(metadatas):
                    self._store[item_id]["metadata"] = metadatas[i]

    def query(
        self,
        query_embeddings: List[List[float]],
        n_results: int = 3,
        include: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if self.use_chroma and self._collection is not None:
            return self._collection.query(
                query_embeddings=query_embeddings,
                n_results=n_results,
                include=include or ["documents", "metadatas", "distances"],
            )

        # Fallback local cosine similarity
        q_emb = query_embeddings[0] if query_embeddings else []
        scored = []

        for item_id, data in self._store.items():
            emb = data.get("embedding")
            if not emb or not q_emb:
                continue
            similarity = self._cosine_similarity(q_emb, emb)
            # Distance in Chroma cosine space is 1 - similarity
            distance = max(0.0, 1.0 - similarity)
            scored.append((distance, item_id, data.get("document", ""), data.get("metadata", {})))

        scored.sort(key=lambda x: x[0])
        top = scored[:n_results]

        return {
            "ids": [[x[1] for x in top]],
            "distances": [[x[0] for x in top]],
            "documents": [[x[2] for x in top]],
            "metadatas": [[x[3] for x in top]],
        }

    def get(self) -> Dict[str, Any]:
        if self.use_chroma and self._collection is not None:
            return self._collection.get()
        return {"ids": list(self._store.keys())}

    @staticmethod
    def _cosine_similarity(v1: List[float], v2: List[float]) -> float:
        if len(v1) != len(v2) or not v1:
            return 0.0
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)
