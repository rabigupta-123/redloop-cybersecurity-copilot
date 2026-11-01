"""Read-only audit log reporting for Markdown and the local dashboard."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

MAX_REPORT_ROWS = 5_000
MAX_DASHBOARD_ROWS = 100
MAX_DETAIL_CHARS = 8_000
_SAFE_SLUG = re.compile(r"[^A-Za-z0-9_-]+")
_AUDIT_COLUMNS = (
    "id",
    "timestamp",
    "target",
    "action",
    "module",
    "status",
    "details",
    "scope_entry",
)


class AuditReader:
    """Bounded, read-only queries over the existing audit database."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)

    def entries(
        self,
        target: str | None = None,
        limit: int = MAX_DASHBOARD_ROWS,
        module: str | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        if not 1 <= limit <= MAX_REPORT_ROWS:
            raise ValueError(f"limit must be between 1 and {MAX_REPORT_ROWS}")
        if not self.db_path.is_file():
            return [], False

        filters: list[str] = []
        params: list[Any] = []
        if target is not None:
            filters.append("target = ?")
            params.append(target)
        module_filters = {
            "recon": "(module IN ('nmap', 'recon') OR action = 'recon')",
            "webapp": "(module = 'webapp' OR action = 'web_test')",
            "exploit": "(module = 'exploit' OR action = 'exploit')",
            "forensics": "module = 'forensics'",
            "executor": "module = 'executor'",
            "memory": "module = 'memory'",
        }
        if module in module_filters:
            filters.append(module_filters[module])
        elif module:
            filters.append("module = ?")
            params.append(module)
        where = f" WHERE {' AND '.join(filters)}" if filters else ""
        params.append(limit + 1)
        uri = f"{self.db_path.resolve().as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                f"SELECT id, timestamp, target, action, module, status, details, scope_entry "
                f"FROM audit_log{where} ORDER BY id DESC LIMIT ?",
                tuple(params),
            ).fetchall()
        truncated = len(rows) > limit
        results = [dict(row) for row in rows[:limit]]
        for row in results:
            raw_details = row["details"]
            if raw_details and len(raw_details) > MAX_DETAIL_CHARS:
                row["details"] = {
                    "truncated": True,
                    "preview": raw_details[:MAX_DETAIL_CHARS],
                }
                continue
            try:
                row["details"] = json.loads(raw_details or "{}")
            except (TypeError, ValueError, RecursionError):
                row["details"] = {"unparsed_details": str(raw_details)[:2_000]}
        return results, truncated

    def targets(self, limit: int = MAX_REPORT_ROWS) -> list[str]:
        if not 1 <= limit <= MAX_REPORT_ROWS:
            raise ValueError(f"limit must be between 1 and {MAX_REPORT_ROWS}")
        if not self.db_path.is_file():
            return []
        uri = f"{self.db_path.resolve().as_uri()}?mode=ro"
        with sqlite3.connect(uri, uri=True, timeout=5) as conn:
            rows = conn.execute(
                "SELECT DISTINCT target FROM audit_log ORDER BY target LIMIT ?",
                (limit,),
            ).fetchall()
        return [str(row[0]) for row in rows]


class AuditReportGenerator:
    """Generate reproducible Markdown from existing audit records."""

    def __init__(self, db_path: str | Path, reports_dir: str | Path):
        self.reader = AuditReader(db_path)
        self.reports_dir = Path(reports_dir)

    def generate(
        self, target: str, output_path: str | Path | None = None
    ) -> Path:
        if not target or len(target) > 2_048:
            raise ValueError("target must contain 1-2048 characters")
        rows, truncated = self.reader.entries(target=target, limit=MAX_REPORT_ROWS)
        rows.reverse()
        destination = Path(output_path) if output_path is not None else self._default_path(target)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            self._render(target, rows, truncated), encoding="utf-8"
        )
        return destination

    def _default_path(self, target: str) -> Path:
        slug = _SAFE_SLUG.sub("_", target).strip("_")[:48] or "target"
        suffix = hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]
        return self.reports_dir / f"{slug}-{suffix}-report.md"

    @staticmethod
    def _render(target: str, rows: list[dict[str, Any]], truncated: bool) -> str:
        counts: dict[str, int] = {}
        for row in rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        lines = [
            "# RedLoop Audit Activity Report",
            "",
            f"**Target:** {_markdown_text(target)}",
            f"**Records included:** {len(rows)}",
            "",
            "This report summarizes recorded activity; a successful action is not "
            "necessarily a security finding.",
            "",
            "## Status summary",
            "",
        ]
        if counts:
            lines.extend(f"- **{_markdown_text(status)}:** {count}" for status, count in sorted(counts.items()))
        else:
            lines.append("No audit records were found for this target.")
        lines.extend(["", "## Activity", ""])
        if truncated:
            lines.extend(
                [
                    f"> Results are limited to the most recent {MAX_REPORT_ROWS} records.",
                    "",
                ]
            )
        for row in rows:
            lines.extend(
                [
                    f"### {_markdown_text(row['module'])} — "
                    f"{_markdown_text(row['action'])}",
                    "",
                    f"- **Time:** {_markdown_text(row['timestamp'])}",
                    f"- **Status:** {_markdown_text(row['status'])}",
                    f"- **Scope entry:** {_markdown_text(row['scope_entry'] or 'n/a')}",
                    "- **Details:**",
                    "",
                    "```json",
                    _json_for_markdown(row["details"]),
                    "```",
                    "",
                ]
            )
        lines.extend(["## Blocked activity", ""])
        blocked = [row for row in rows if row["status"] == "blocked"]
        if not blocked:
            lines.append("No blocked activity was recorded for this target.")
        else:
            lines.extend(
                f"- {_markdown_text(row['timestamp'])}: "
                f"{_markdown_text(row['action'])} was blocked."
                for row in blocked
            )
        return "\n".join(lines) + "\n"


def _markdown_text(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ")
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _json_for_markdown(value: Any) -> str:
    try:
        rendered = json.dumps(value, ensure_ascii=True, indent=2, default=str)
    except (TypeError, ValueError, RecursionError):
        rendered = json.dumps({"unavailable": True})
    return rendered.replace("```", "` ` `")
