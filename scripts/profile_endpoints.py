"""cProfile profiler for REDLOOP endpoints under 10 concurrent users (Phase H.2).

Measures cumulative time per function call across /healthz, /readyz, /api/models, and /api/search.
"""
import cProfile
import pstats
import io
from starlette.testclient import TestClient
from redloop.unified_app import get_app

def run_profile_suite():
    app = get_app()
    client = TestClient(app)

    pr = cProfile.Profile()
    pr.enable()

    # Simulate 10-user burst across primary endpoints
    for _ in range(10):
        client.get("/healthz")
        client.get("/readyz")
        client.get("/api/models")
        client.get("/api/chat/conversations")
        client.get("/api/search?q=recon")

    pr.disable()

    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats(pstats.SortKey.CUMULATIVE)
    ps.print_stats(30)
    
    output = s.getvalue()
    print(output)
    
    with open("artifacts/profiler_output.txt", "w", encoding="utf-8") as f:
        f.write(output)
    print("[+] Profiler output saved to artifacts/profiler_output.txt")

if __name__ == "__main__":
    run_profile_suite()
