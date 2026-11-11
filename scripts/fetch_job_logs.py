"""
scripts/fetch_job_logs.py
Fetches logs for GitHub Actions jobs by safely handling redirects without leaking the Auth header to storage CDN.
"""
import subprocess
import urllib.request
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

class NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        # Strip authorization when redirected to external storage host
        if new_req and 'Authorization' in new_req.headers:
            del new_req.headers['Authorization']
        return new_req

def fetch_logs(job_id=130338945276):
    token = get_github_token()
    url = f"https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/actions/jobs/{job_id}/logs"
    
    opener = urllib.request.build_opener(NoAuthRedirect)
    req = urllib.request.Request(
        url,
        headers={
            'Authorization': f'Bearer {token}',
            'User-Agent': 'RedLoop-Log-Fetcher'
        }
    )
    
    with opener.open(req) as resp:
        content = resp.read().decode('utf-8', errors='replace')
        
    print(f"Fetched {len(content)} characters of log.")
    with open("artifacts/nightly_run_log.txt", "w", encoding="utf-8") as f:
        f.write(content)
    print("Saved to artifacts/nightly_run_log.txt")

    # Extract pytest failures
    failures = []
    capture = False
    fail_summary = []
    
    for line in content.splitlines():
        if "FAILED " in line or "ERROR " in line:
            failures.append(line)
        if "=== FAILURES ===" in line or "=== ERRORS ===" in line:
            capture = True
        if "=== short test summary info ===" in line:
            capture = True
        if capture:
            fail_summary.append(line)
            if len(fail_summary) > 200:
                pass # keep collecting
                
    print("\n--- DETECTED FAILURES IN LOG ---")
    for f in failures[:50]:
        print(f)
    print(f"\nTotal failure lines: {len(failures)}")

if __name__ == '__main__':
    job_id = int(sys.argv[1]) if len(sys.argv) > 1 else 130338945276
    fetch_logs(job_id)

