import json
import urllib.request

for run_id in [42787137469, 42787164359]:
    url = f"https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/actions/runs/{run_id}/jobs"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            for j in data.get("jobs", []):
                print(f"Run {run_id} ({j['name']}): status={j['status']}, conclusion={j['conclusion']}")
                for s in j.get("steps", []):
                    print(f"   step '{s['name']}': status={s['status']}, conclusion={s['conclusion']}")
    except Exception as e:
        print(f"Error for {run_id}: {e}")

