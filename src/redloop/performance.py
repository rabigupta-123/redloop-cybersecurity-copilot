"""
Performance Monitoring Dashboard for RedLoop Mythos Agent.
Real-time metrics: latency, confidence, learning rate, token usage.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class QueryMetric:
    """Single query performance record."""
    timestamp: datetime
    mode: str  # general, ctf_crypto, ctf_web, etc.
    latency_ms: float
    confidence: float
    tokens_used: int
    success: bool
    verified: bool
    agents_used: int  # multi-agent debate count
    tools_called: List[str] = field(default_factory=list)
    error: Optional[str] = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    token_usage_reported: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "mode": self.mode,
            "latency_ms": round(self.latency_ms, 2),
            "confidence": round(self.confidence, 1),
            "tokens_used": self.tokens_used,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "token_usage_reported": self.token_usage_reported,
            "success": self.success,
            "verified": self.verified,
            "agents_used": self.agents_used,
            "tools_called": self.tools_called,
            "error": self.error,
        }


class MetricsCollector:
    """Collects and aggregates real-time performance metrics."""

    def __init__(self, window_size: int = 1000):
        self.metrics: deque[QueryMetric] = deque(maxlen=window_size)
        self.start_time = utc_now()

        # Cumulative counters
        self.total_queries = 0
        self.total_successes = 0
        self.total_failures = 0
        self.total_tokens = 0
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.token_usage_reported_queries = 0
        self.total_latency_ms = 0.0

        # Per-mode tracking
        self.mode_stats: Dict[str, Dict[str, Any]] = {}

        # Learning tracking
        self.experiences_stored = 0
        self.errors_logged = 0
        self.feedback_received = 0

        # Hourly buckets for trends
        self.hourly_buckets: Dict[str, Dict[str, Any]] = {}

    def record(self, metric: QueryMetric) -> None:
        """Record a single query metric."""
        self.metrics.append(metric)

        # Update cumulative
        self.total_queries += 1
        if metric.success:
            self.total_successes += 1
        else:
            self.total_failures += 1
        self.total_tokens += metric.tokens_used
        self.total_prompt_tokens += metric.prompt_tokens
        self.total_completion_tokens += metric.completion_tokens
        if metric.token_usage_reported:
            self.token_usage_reported_queries += 1
        self.total_latency_ms += metric.latency_ms

        # Mode-specific stats
        mode = metric.mode or "general"
        if mode not in self.mode_stats:
            self.mode_stats[mode] = {
                "count": 0,
                "avg_latency": 0.0,
                "avg_confidence": 0.0,
                "total_tokens": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "success_count": 0,
            }

        ms = self.mode_stats[mode]
        n = ms["count"]
        ms["count"] += 1
        ms["avg_latency"] = (ms["avg_latency"] * n + metric.latency_ms) / ms["count"]
        ms["avg_confidence"] = (ms["avg_confidence"] * n + metric.confidence) / ms["count"]
        ms["total_tokens"] += metric.tokens_used
        ms["prompt_tokens"] += metric.prompt_tokens
        ms["completion_tokens"] += metric.completion_tokens
        if metric.success:
            ms["success_count"] += 1

        # Hourly bucket
        hour_key = metric.timestamp.strftime("%Y-%m-%d %H:00")
        if hour_key not in self.hourly_buckets:
            self.hourly_buckets[hour_key] = {
                "queries": 0,
                "avg_latency": 0.0,
                "avg_confidence": 0.0,
                "success_rate": 0.0,
            }

        hb = self.hourly_buckets[hour_key]
        prev_n = hb["queries"]
        hb["queries"] += 1
        hb["avg_latency"] = (hb["avg_latency"] * prev_n + metric.latency_ms) / hb["queries"]
        hb["avg_confidence"] = (hb["avg_confidence"] * prev_n + metric.confidence) / hb["queries"]
        if metric.success:
            hb["success_rate"] = (hb["success_rate"] * prev_n + 100.0) / hb["queries"]
        else:
            hb["success_rate"] = (hb["success_rate"] * prev_n) / hb["queries"]

    def record_learning_event(self, event_type: str) -> None:
        """Track learning events."""
        if event_type == "experience_stored":
            self.experiences_stored += 1
        elif event_type == "error_logged":
            self.errors_logged += 1
        elif event_type == "feedback":
            self.feedback_received += 1

    def get_summary(self) -> Dict[str, Any]:
        """Get overall summary performance statistics."""
        uptime_seconds = (utc_now() - self.start_time).total_seconds()

        avg_latency = self.total_latency_ms / max(self.total_queries, 1)
        avg_confidence = (
            sum(m.confidence for m in self.metrics) / max(len(self.metrics), 1)
            if self.metrics
            else 0.0
        )
        success_rate = (self.total_successes / max(self.total_queries, 1)) * 100

        recent = list(self.metrics)[-50:]
        recent_avg_latency = (
            sum(m.latency_ms for m in recent) / max(len(recent), 1) if recent else 0.0
        )
        recent_avg_confidence = (
            sum(m.confidence for m in recent) / max(len(recent), 1) if recent else 0.0
        )

        sorted_latencies = sorted(m.latency_ms for m in self.metrics)
        p50 = self._percentile(sorted_latencies, 50)
        p95 = self._percentile(sorted_latencies, 95)
        p99 = self._percentile(sorted_latencies, 99)

        return {
            "uptime_seconds": round(uptime_seconds),
            "total_queries": self.total_queries,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "success_rate_percent": round(success_rate, 2),
            "avg_latency_ms": round(avg_latency, 2),
            "recent_avg_latency_ms": round(recent_avg_latency, 2),
            "p50_latency_ms": round(p50, 2),
            "p95_latency_ms": round(p95, 2),
            "p99_latency_ms": round(p99, 2),
            "avg_confidence": round(avg_confidence, 2),
            "recent_avg_confidence": round(recent_avg_confidence, 2),
            "total_tokens_used": self.total_tokens,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "token_usage_reported_queries": self.token_usage_reported_queries,
            "experiences_stored": self.experiences_stored,
            "errors_logged": self.errors_logged,
            "feedback_received": self.feedback_received,
            "learning_rate": round(
                (self.experiences_stored + self.errors_logged)
                / max(self.total_queries, 1)
                * 100,
                2,
            ),
            "active_modes": len(self.mode_stats),
        }

    def get_mode_breakdown(self) -> Dict[str, Any]:
        """Return per-mode breakdown statistics."""
        result = {}
        for mode, stats in self.mode_stats.items():
            result[mode] = {
                "query_count": stats["count"],
                "avg_latency_ms": round(stats["avg_latency"], 2),
                "avg_confidence": round(stats["avg_confidence"], 2),
                "success_rate": round(
                    stats["success_count"] / max(stats["count"], 1) * 100, 2
                ),
                "total_tokens": stats["total_tokens"],
                "prompt_tokens": stats["prompt_tokens"],
                "completion_tokens": stats["completion_tokens"],
            }
        return result

    def get_trend_data(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get hourly trend data for charts."""
        now = utc_now()
        trend = []
        for i in range(hours, 0, -1):
            hour_dt = now - timedelta(hours=i)
            key = hour_dt.strftime("%Y-%m-%d %H:00")
            bucket = self.hourly_buckets.get(
                key,
                {
                    "queries": 0,
                    "avg_latency": 0.0,
                    "avg_confidence": 0.0,
                    "success_rate": 0.0,
                },
            )
            trend.append(
                {
                    "hour": hour_dt.strftime("%H:00"),
                    "date": hour_dt.strftime("%m/%d"),
                    "queries": bucket["queries"],
                    "avg_latency_ms": round(bucket["avg_latency"], 2),
                    "avg_confidence": round(bucket["avg_confidence"], 2),
                    "success_rate": round(bucket["success_rate"], 2),
                }
            )
        return trend

    def get_recent_errors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent failed queries."""
        errors = [m for m in self.metrics if not m.success][-limit:]
        return [m.to_dict() for m in reversed(errors)]

    def get_recent_metrics(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent query metrics."""
        recent = list(self.metrics)[-limit:]
        return [m.to_dict() for m in reversed(recent)]

    @staticmethod
    def _percentile(sorted_data: List[float], percentile: float) -> float:
        if not sorted_data:
            return 0.0
        k = (len(sorted_data) - 1) * (percentile / 100.0)
        f = int(k)
        c = min(f + 1, len(sorted_data) - 1)
        d = k - f
        return sorted_data[f] + d * (sorted_data[c] - sorted_data[f])


# Global singleton instance
metrics_collector = MetricsCollector()


def record_query_metric(
    mode: str,
    latency_ms: float,
    confidence: float,
    tokens_used: int,
    success: bool = True,
    verified: bool = False,
    agents_used: int = 1,
    tools_called: Optional[List[str]] = None,
    error: Optional[str] = None,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    token_usage_reported: bool = False,
) -> None:
    """Convenience helper to record metrics across the system."""
    metric = QueryMetric(
        timestamp=utc_now(),
        mode=mode,
        latency_ms=latency_ms,
        confidence=confidence,
        tokens_used=tokens_used,
        success=success,
        verified=verified,
        agents_used=agents_used,
        tools_called=tools_called or [],
        error=error,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        token_usage_reported=token_usage_reported,
    )
    metrics_collector.record(metric)


class TokenUsageStore:
    """Persist provider-reported chat token counts without storing prompts."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_token_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    prompt_tokens INTEGER NOT NULL,
                    completion_tokens INTEGER NOT NULL,
                    total_tokens INTEGER NOT NULL,
                    usage_reported INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_token_usage_timestamp "
                "ON chat_token_usage(timestamp DESC)"
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path, timeout=5)

    def record(
        self,
        *,
        mode: str,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        usage_reported: bool,
    ) -> None:
        counts = (prompt_tokens, completion_tokens, total_tokens)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        ):
            raise ValueError("Token counts must be non-negative integers.")
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO chat_token_usage
                    (timestamp, mode, provider, model, prompt_tokens,
                     completion_tokens, total_tokens, usage_reported)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    utc_now().isoformat(),
                    mode,
                    provider,
                    model,
                    prompt_tokens,
                    completion_tokens,
                    total_tokens,
                    int(usage_reported),
                ),
            )

    def get_summary(self, recent_limit: int = 20) -> Dict[str, Any]:
        with self._connect() as connection:
            connection.row_factory = sqlite3.Row
            totals = connection.execute(
                """
                SELECT COUNT(*) AS requests,
                       SUM(usage_reported) AS reported_requests,
                       SUM(prompt_tokens) AS prompt_tokens,
                       SUM(completion_tokens) AS completion_tokens,
                       SUM(total_tokens) AS total_tokens
                FROM chat_token_usage
                """
            ).fetchone()
            providers = connection.execute(
                """
                SELECT provider, COUNT(*) AS requests,
                       SUM(usage_reported) AS reported_requests,
                       SUM(prompt_tokens) AS prompt_tokens,
                       SUM(completion_tokens) AS completion_tokens,
                       SUM(total_tokens) AS total_tokens
                FROM chat_token_usage
                GROUP BY provider
                ORDER BY total_tokens DESC, provider
                """
            ).fetchall()
            modes = connection.execute(
                """
                SELECT mode, COUNT(*) AS requests,
                       SUM(usage_reported) AS reported_requests,
                       SUM(prompt_tokens) AS prompt_tokens,
                       SUM(completion_tokens) AS completion_tokens,
                       SUM(total_tokens) AS total_tokens
                FROM chat_token_usage
                GROUP BY mode
                ORDER BY total_tokens DESC, mode
                """
            ).fetchall()
            recent = connection.execute(
                """
                SELECT timestamp, mode, provider, model, prompt_tokens,
                       completion_tokens, total_tokens, usage_reported
                FROM chat_token_usage
                ORDER BY id DESC LIMIT ?
                """,
                (max(0, min(recent_limit, 100)),),
            ).fetchall()

        def serialize(row: sqlite3.Row) -> Dict[str, Any]:
            return {
                key: row[key] or 0
                for key in (
                    "requests",
                    "reported_requests",
                    "prompt_tokens",
                    "completion_tokens",
                    "total_tokens",
                )
            }

        return {
            **serialize(totals),
            "unreported_requests": (totals["requests"] or 0)
            - (totals["reported_requests"] or 0),
            "providers": [dict(row) for row in providers],
            "modes": [dict(row) for row in modes],
            "recent": [
                {
                    **dict(row),
                    "usage_reported": bool(row["usage_reported"]),
                }
                for row in recent
            ],
            "source": "provider-reported",
        }
