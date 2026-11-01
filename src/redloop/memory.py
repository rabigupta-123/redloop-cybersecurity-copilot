"""Local episodic memory with bounded lexical similarity retrieval.

Memory stores task summaries and symbolic operation names only. It never stores
or returns executable code, payloads, IOC values, or scope authorization.
"""

from __future__ import annotations

import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from redloop.audit import AuditLogger

MAX_TASK_LENGTH = 1_000
MAX_APPROACH_LENGTH = 200
MAX_DETAILS_LENGTH = 512
MAX_RESULTS = 10
MAX_RECORDS = 10_000
_TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_STOP_WORDS = {
    "about", "after", "again", "also", "and", "are", "for", "from", "has",
    "have", "into", "its", "not", "the", "this", "that", "then", "there",
    "they", "was", "were", "with", "you",
}

ModuleName = Literal[
    "executor",
    "forensics",
    "webapp",
    "ctf_simulator",
    "ctf_file_analyzer",
    "recon",
    "tls",
]
Outcome = Literal["success", "failure"]
ALLOWED_MODULES = {
    "executor",
    "forensics",
    "webapp",
    "ctf_simulator",
    "ctf_file_analyzer",
    "recon",
    "tls",
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS episodic_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    task_description TEXT NOT NULL,
    approach TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    module TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_module ON episodic_memory(module);
CREATE INDEX IF NOT EXISTS idx_memory_timestamp ON episodic_memory(timestamp);
"""


class MemoryRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_description: str = Field(min_length=1, max_length=MAX_TASK_LENGTH)
    approach: str = Field(
        min_length=1,
        max_length=MAX_APPROACH_LENGTH,
        pattern=r"^[A-Za-z0-9 _,-]+$",
    )
    outcome: Outcome
    module: ModuleName
    details: str = Field(default="", max_length=MAX_DETAILS_LENGTH)

    @field_validator("task_description", "approach", "details")
    @classmethod
    def _trim_text(cls, value: str, info: ValidationInfo) -> str:
        trimmed = value.strip()
        if info.field_name != "details" and not trimmed:
            raise ValueError(f"{info.field_name} must not be blank")
        return trimmed


class MemoryMatch(BaseModel):
    record: MemoryRecord
    similarity: float = Field(ge=0.0, le=1.0)


class EpisodicMemory:
    """Small local SQLite store with deterministic token-overlap retrieval."""

    def __init__(
        self,
        db_path: str | Path,
        audit: AuditLogger | None = None,
    ):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit = audit
        with self._conn() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def store(self, record: MemoryRecord) -> int:
        record = MemoryRecord.model_validate(record)
        with self._conn() as conn:
            cursor = conn.execute(
                """
                INSERT INTO episodic_memory
                    (timestamp, task_description, approach, outcome, module, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    record.task_description,
                    record.approach,
                    record.outcome,
                    record.module,
                    record.details,
                ),
            )
            conn.execute(
                """
                DELETE FROM episodic_memory
                WHERE id NOT IN (
                    SELECT id FROM episodic_memory ORDER BY id DESC LIMIT ?
                )
                """,
                (MAX_RECORDS,),
            )
            record_id = int(cursor.lastrowid)
        if self.audit:
            self.audit.log(
                record.module,
                "memory_store",
                "memory",
                "success",
                {"outcome": record.outcome},
            )
        return record_id

    def retrieve_similar(
        self,
        task_description: str,
        module: ModuleName | None = None,
        n_results: int = 3,
    ) -> list[MemoryMatch]:
        if not isinstance(task_description, str) or not task_description.strip():
            raise ValueError("task_description must not be empty")
        if len(task_description) > MAX_TASK_LENGTH:
            raise ValueError(f"task_description exceeds {MAX_TASK_LENGTH} characters")
        if module is not None and module not in ALLOWED_MODULES:
            raise ValueError(
                f"module must be one of: {', '.join(sorted(ALLOWED_MODULES))}"
            )
        if isinstance(n_results, bool) or not 1 <= n_results <= MAX_RESULTS:
            raise ValueError(f"n_results must be between 1 and {MAX_RESULTS}")

        query_tokens = self._tokens(task_description)
        if not query_tokens:
            return []
        sql = (
            "SELECT task_description, approach, outcome, module, details "
            "FROM episodic_memory"
        )
        params: tuple[str, ...] = ()
        if module:
            sql += " WHERE module = ?"
            params = (module,)
        sql += " ORDER BY id DESC LIMIT ?"
        with self._conn() as conn:
            rows = conn.execute(sql, (*params, MAX_RECORDS)).fetchall()

        matches: list[MemoryMatch] = []
        for task, approach, outcome, record_module, details in rows:
            record_tokens = self._tokens(task)
            union = query_tokens | record_tokens
            similarity = len(query_tokens & record_tokens) / len(union) if union else 0
            if similarity <= 0:
                continue
            matches.append(
                MemoryMatch(
                    record=MemoryRecord(
                        task_description=task,
                        approach=approach,
                        outcome=outcome,
                        module=record_module,
                        details=details,
                    ),
                    similarity=similarity,
                )
            )
        matches.sort(key=lambda match: match.similarity, reverse=True)
        return matches[:n_results]

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {
            token
            for token in _TOKEN_RE.findall(text.casefold())
            if token not in _STOP_WORDS
        }
