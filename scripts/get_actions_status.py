import json
import urllib.request

url = "https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/actions/runs?per_page=10"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        for r in data.get("workflow_runs", []):
            print(f"Branch: {r['head_branch']} | Status: {r['status']} | Conclusion: {r['conclusion']} | URL: {r['html_url']} | Created: {r['created_at']} | Commit: {r['head_sha'][:7]}")
except Exception as e:
    print("Error querying GitHub API:", e)
