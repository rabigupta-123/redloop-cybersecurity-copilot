"""Live request path profiler using cProfile over 10 concurrent threads (Phase H.2).

Measures client/server interaction times and cumulative bottlenecks.
"""
import cProfile
import pstats
import io
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://127.0.0.1:8765"
ENDPOINTS = [
    "/healthz",
    "/readyz",
    "/api/models",
    "/api/chat/conversations",
    "/api/search?q=recon",
]

def hit_endpoint(ep: str):
    try:
        req = urllib.request.Request(f"{BASE_URL}{ep}", headers={"Origin": BASE_URL, "X-Operator-ID": "prof-user"})
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return resp.read()
    except Exception as e:
        return str(e)

def run():
    pr = cProfile.Profile()
    pr.enable()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for _ in range(5):
            for ep in ENDPOINTS:
                futures.append(executor.submit(hit_endpoint, ep))
        for f in futures:
            f.result()

    pr.disable()

    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats(pstats.SortKey.CUMULATIVE)
    ps.print_stats(25)
    output = s.getvalue()
    
    with open("artifacts/profiler_output.txt", "w", encoding="utf-8") as out_f:
        out_f.write(output)
    print("[+] Profiler output saved to artifacts/profiler_output.txt")
    print(output)

if __name__ == "__main__":
    run()
