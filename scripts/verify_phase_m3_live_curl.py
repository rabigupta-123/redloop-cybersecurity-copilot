"""Phase M.3 — Live Server REST & Chat Entry Point Wiring Proof.

Starts a real FastAPI/Uvicorn server on loopback HTTP, executes `curl.exe -s -i`
against both the live REST OSINT endpoint (`POST /api/osint/email`) and the live
Chat endpoint (`POST /api/chat/message`) with out-of-scope person identifiers,
captures the verbatim raw HTTP 403 responses (status line, headers, JSON body),
and queries the live SQLite `audit_log` table to display the matching
`BLOCKED_SCOPE_REQUIRED` audit rows and verify hash-chain integrity.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from typing import Any

import uvicorn

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from redloop.audit import AuditLogger
from redloop.dashboard import create_app


def _find_free_port(preferred: int = 8769) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])


def main() -> int:
    artifacts_dir = REPO_ROOT / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    db_path = artifacts_dir / "phase_m3_live_audit.db"
    if db_path.exists():
        db_path.unlink()

    app = create_app(
        db_path=str(db_path),
        operator_identifiers=["rabi.operator@redloop.io", "rabi_sec_ops"],
    )

    port = _find_free_port(8769)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server socket readiness
    deadline = time.time() + 15.0
    while time.time() < deadline:
        if server.started:
            break
        time.sleep(0.1)
    if not server.started:
        raise RuntimeError("Uvicorn server failed to start within 15s")

    base_url = f"http://127.0.0.1:{port}"

    try:
        # 1. Live curl against REST OSINT endpoint (POST /api/osint/email)
        rest_payload = json.dumps({"email": "stranger@unscoped-external.org"})
        rest_cmd = [
            "curl.exe",
            "-s",
            "-i",
            "-X",
            "POST",
            f"{base_url}/api/osint/email",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"Origin: {base_url}",
            "-d",
            rest_payload,
        ]
        rest_proc = subprocess.run(
            rest_cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        raw_rest_http = rest_proc.stdout.replace("\r\n", "\n").strip()

        # 2. Live curl against Chat endpoint (POST /api/chat/message)
        chat_payload = json.dumps(
            {
                "message": "Investigate username @unscoped_target_handle_99",
                "conversation_id": "live-m3-chat",
            }
        )
        chat_cmd = [
            "curl.exe",
            "-s",
            "-i",
            "-X",
            "POST",
            f"{base_url}/api/chat/message",
            "-H",
            "Content-Type: application/json",
            "-H",
            f"Origin: {base_url}",
            "-d",
            chat_payload,
        ]
        chat_proc = subprocess.run(
            chat_cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        raw_chat_http = chat_proc.stdout.replace("\r\n", "\n").strip()

    finally:
        server.should_exit = True
        thread.join(timeout=5.0)

    # 3. Query the SQLite audit_log rows written by the live requests
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = [
        dict(r)
        for r in conn.execute(
            "SELECT id, timestamp, target, action, module, status, details, prev_hash, event_hash "
            "FROM audit_log ORDER BY id ASC"
        ).fetchall()
    ]
    conn.close()

    chain_valid = AuditLogger(str(db_path)).verify_chain()

    rest_audit_row = next(
        (r for r in rows if r["target"] == "stranger@unscoped-external.org"),
        None,
    )
    chat_audit_row = next(
        (r for r in rows if "unscoped_target_handle_99" in r["target"]),
        None,
    )

    transcript_data: dict[str, Any] = {
        "server_base_url": base_url,
        "audit_db_path": str(db_path),
        "hash_chain_valid": chain_valid,
        "rest_entry_point": {
            "curl_command": (
                f'curl.exe -s -i -X POST {base_url}/api/osint/email '
                f'-H "Content-Type: application/json" -H "Origin: {base_url}" '
                f"-d '{rest_payload}'"
            ),
            "raw_http_response": raw_rest_http,
            "matching_audit_row": rest_audit_row,
        },
        "chat_entry_point": {
            "curl_command": (
                f'curl.exe -s -i -X POST {base_url}/api/chat/message '
                f'-H "Content-Type: application/json" -H "Origin: {base_url}" '
                f"-d '{chat_payload}'"
            ),
            "raw_http_response": raw_chat_http,
            "matching_audit_row": chat_audit_row,
        },
        "all_audit_rows": rows,
    }

    out_json = artifacts_dir / "phase_m3_live_wiring_transcripts.json"
    out_json.write_text(json.dumps(transcript_data, indent=2) + "\n", encoding="utf-8")

    text_lines = [
        "=== PHASE M.3 LIVE REST & CHAT ENTRY POINT WIRING TRANSCRIPTS ===",
        "",
        "--- [1] REST ENTRY POINT (POST /api/osint/email) ---",
        f"$ {transcript_data['rest_entry_point']['curl_command']}",
        "",
        raw_rest_http,
        "",
        "Matching SQLite audit_log Row (REST):",
        json.dumps(rest_audit_row, indent=2),
        "",
        "--- [2] CHAT ENTRY POINT (POST /api/chat/message) ---",
        f"$ {transcript_data['chat_entry_point']['curl_command']}",
        "",
        raw_chat_http,
        "",
        "Matching SQLite audit_log Row (Chat):",
        json.dumps(chat_audit_row, indent=2),
        "",
        f"Audit Hash-Chain Integrity (`AuditLogger.verify_chain()`): {chain_valid}",
    ]
    out_txt = artifacts_dir / "phase_m3_live_wiring_transcripts.txt"
    out_txt.write_text("\n".join(text_lines) + "\n", encoding="utf-8")

    print("\n".join(text_lines))
    if not ("403" in raw_rest_http and "403" in raw_chat_http and rest_audit_row and chat_audit_row and chain_valid):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
