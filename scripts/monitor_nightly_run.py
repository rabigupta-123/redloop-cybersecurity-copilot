"""
scripts/monitor_nightly_run.py
Monitors and displays the live status of the latest run of nightly_full_suite.yml,
and fetches step logs upon completion.
"""
import subprocess
import urllib.request
import urllib.error
import json
import time
import sys

def get_github_token():
    p = subprocess.run(
        ['git', 'credential', 'fill'],
        input='protocol=https\nhost=github.com\n\n',
        capture_output=True,
        text=True,
        check=True
    )
    for line in p.stdout.splitlines():
        if line.startswith('password='):
            return line.split('=', 1)[1]
    raise RuntimeError("No token found")

def api_get(url):
    token = get_github_token()
    req = urllib.request.Request(
        url,
        headers={
            'Authorization': f'Bearer {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'RedLoop-Monitor'
        }
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode('utf-8'))

def get_job_log(job_id):
    token = get_github_token()
    url = f"https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/actions/jobs/{job_id}/logs"
    req = urllib.request.Request(
        url,
        headers={
            'Authorization': f'Bearer {token}',
            'User-Agent': 'RedLoop-Monitor'
        }
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        return f"Error fetching logs: {e}"

def check_run(run_id=42964655352):
    run = api_get(f"https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/actions/runs/{run_id}")
    print(f"Run ID: {run['id']}")
    print(f"URL: {run['html_url']}")
    print(f"Status: {run['status']}")
    print(f"Conclusion: {run['conclusion']}")
    print(f"Updated At: {run['updated_at']}")

    jobs_data = api_get(run['jobs_url'])
    for j in jobs_data.get('jobs', []):
        print(f"\nJob: {j['name']} (ID: {j['id']}) [status={j['status']}, conclusion={j['conclusion']}]")
        for s in j.get('steps', []):
            print(f"  Step '{s['name']}': status={s['status']}, conclusion={s['conclusion']}")

        if j['status'] == 'completed':
            print("\n--- JOB LOG SUMMARY (Last 80 lines) ---")
            raw_log = get_job_log(j['id'])
            lines = raw_log.splitlines()
            for l in lines[-80:]:
                print(l)
            with open("artifacts/nightly_run_log.txt", "w", encoding="utf-8") as f:
                f.write(raw_log)
            print("\nFull log saved to artifacts/nightly_run_log.txt")

    return run

if __name__ == '__main__':
    check_run()
