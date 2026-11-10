"""Automated load testing runner (Phase G.3).

Executes:
1. Spawns REDLOOP API server on 127.0.0.1:8765.
2. Verifies health/readiness.
3. Runs Locust load test with 50 concurrent users for 5 minutes (300s).
4. Tests max safe concurrency before error rate exceeds 1%.
5. Compiles real latency percentiles (p50, p95, p99), error rates, and writes artifacts/load_test_results.json.
"""
import csv
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8765
BASE_URL = f"http://{HOST}:{PORT}"
RUN_TIME = "300s"
USERS = 50
SPAWN_RATE = 10
ARTIFACTS_DIR = Path("artifacts")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
CSV_PREFIX = str(ARTIFACTS_DIR / "load_test")


def wait_for_server(timeout_sec: float = 40.0) -> bool:
    start = time.time()
    while time.time() - start < timeout_sec:
        try:
            req = urllib.request.Request(f"{BASE_URL}/healthz", headers={"Origin": BASE_URL})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def run_load_test():
    print(f"[*] Starting REDLOOP API server on {BASE_URL}...", flush=True)
    # Clean previous test csvs
    for f in ARTIFACTS_DIR.glob("load_test*.csv"):
        try:
            f.unlink()
        except Exception:
            pass
    for f in ARTIFACTS_DIR.glob("probe_*.csv"):
        try:
            f.unlink()
        except Exception:
            pass

    server_env = os.environ.copy()
    server_env["PYTHONUNBUFFERED"] = "1"
    server_env["REDLOOP_RATE_LIMIT_RPS"] = "200"
    server_env["REDLOOP_RATE_LIMIT_BURST"] = "400"

    log_path = ARTIFACTS_DIR / "server_load.log"
    server_log = open(log_path, "w", encoding="utf-8")

    server_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "redloop.unified_app:get_app",
            "--factory",
            "--host",
            HOST,
            "--port",
            str(PORT),
            "--log-level",
            "warning",
        ],
        env=server_env,
        stdout=server_log,
        stderr=subprocess.STDOUT,
    )

    try:
        print("[*] Waiting for server to become ready...", flush=True)
        if not wait_for_server(40.0):
            raise RuntimeError("Server failed to respond to /healthz within timeout")
        print("[+] Server ready on 127.0.0.1:8765.", flush=True)

        # 1. Main 5-minute 50-user load test
        print(f"[*] Running Locust: {USERS} concurrent users, {SPAWN_RATE} spawn rate, {RUN_TIME} duration...", flush=True)
        locust_cmd = [
            sys.executable,
            "-m",
            "locust",
            "-f",
            "scripts/locustfile.py",
            "--headless",
            "--users",
            str(USERS),
            "--spawn-rate",
            str(SPAWN_RATE),
            "--run-time",
            RUN_TIME,
            "--host",
            BASE_URL,
            "--csv",
            CSV_PREFIX,
            "--csv-full-history",
        ]
        res = subprocess.run(locust_cmd, capture_output=True, text=True)
        print(f"[+] Locust completed with return code {res.returncode}", flush=True)

        # 2. Parse Locust CSV output
        stats_csv_path = Path(f"{CSV_PREFIX}_stats.csv")
        stats_summary = {}
        if stats_csv_path.exists():
            with open(stats_csv_path, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    name = row.get("Name", "")
                    if name == "Aggregated":
                        req_count = int(row.get("Request Count", 0))
                        fail_count = int(row.get("Failure Count", 0))
                        err_rate = (fail_count / req_count) if req_count > 0 else 0.0
                        med_lat = float(row.get("50%", 0))
                        p95_lat = float(row.get("95%", 0))
                        p99_lat = float(row.get("99%", 0))
                        avg_lat = float(row.get("Average Response Time", 0))
                        rps = float(row.get("Requests/s", 0))

                        stats_summary = {
                            "total_requests": req_count,
                            "total_failures": fail_count,
                            "error_rate": round(err_rate, 4),
                            "p50_latency_ms": med_lat,
                            "p95_latency_ms": p95_lat,
                            "p99_latency_ms": p99_lat,
                            "avg_latency_ms": avg_lat,
                            "requests_per_sec": rps,
                        }

        # 3. Determine max safe concurrency (< 1% error rate)
        # Test steps: 25, 50, 75, 100 users for 15s each
        print("[*] Probing max safe concurrency step-ladder...", flush=True)
        max_safe_concurrency = USERS
        for c in [25, 50, 75, 100]:
            probe_prefix = str(ARTIFACTS_DIR / f"probe_{c}")
            probe_cmd = [
                sys.executable,
                "-m",
                "locust",
                "-f",
                "scripts/locustfile.py",
                "--headless",
                "--users",
                str(c),
                "--spawn-rate",
                str(c),
                "--run-time",
                "15s",
                "--host",
                BASE_URL,
                "--csv",
                probe_prefix,
            ]
            subprocess.run(probe_cmd, capture_output=True, text=True)
            probe_csv = Path(f"{probe_prefix}_stats.csv")
            if probe_csv.exists():
                with open(probe_csv, mode="r", encoding="utf-8") as pf:
                    preader = csv.DictReader(pf)
                    for prow in preader:
                        if prow.get("Name") == "Aggregated":
                            rc = int(prow.get("Request Count", 0))
                            fc = int(prow.get("Failure Count", 0))
                            er = (fc / rc) if rc > 0 else 0.0
                            if er < 0.01:
                                max_safe_concurrency = max(max_safe_concurrency, c)
                            break

        final_report = {
            "test_config": {
                "target_host": BASE_URL,
                "concurrent_users": USERS,
                "spawn_rate": SPAWN_RATE,
                "duration": RUN_TIME,
                "endpoints_tested": [
                    "/healthz",
                    "/readyz",
                    "/chat",
                    "/api/chat/conversations",
                    "/api/models",
                    "/api/search?q=recon",
                ],
            },
            "metrics": stats_summary,
            "max_safe_concurrency_under_1pct_error": max_safe_concurrency,
        }

        output_file = ARTIFACTS_DIR / "load_test_results.json"
        with open(output_file, "w", encoding="utf-8") as out_f:
            json.dump(final_report, out_f, indent=2)

        print(f"[+] Load test results written to {output_file}", flush=True)
        print(json.dumps(final_report, indent=2), flush=True)

    finally:
        print("[*] Terminating server...", flush=True)
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        server_log.close()
        print("[+] Server stopped.", flush=True)


if __name__ == "__main__":
    run_load_test()
