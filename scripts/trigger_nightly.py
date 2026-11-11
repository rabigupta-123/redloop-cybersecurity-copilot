"""
scripts/trigger_nightly.py
Lists workflows, triggers workflow_dispatch for nightly_full_suite.yml, and polls status.
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
    raise RuntimeError("No password/token found in git credential helper")

def api_request(url, method="GET", data=None):
    token = get_github_token()
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'RedLoop-Nightly-Runner'
    }
    req = urllib.request.Request(url, headers=headers, method=method)
    if data:
        req.data = json.dumps(data).encode('utf-8')
        req.headers['Content-Type'] = 'application/json'
    with urllib.request.urlopen(req) as resp:
        if resp.status == 204:
            return None
        return json.loads(resp.read().decode('utf-8'))

def list_workflows():
    data = api_request('https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/actions/workflows')
    for wf in data.get('workflows', []):
        print(f"ID: {wf['id']}, Name: '{wf['name']}', State: {wf['state']}, Path: {wf['path']}")
    return data.get('workflows', [])

def trigger_workflow(workflow_id_or_file, ref="feat/connectors-bounty"):
    url = f'https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/actions/workflows/{workflow_id_or_file}/dispatches'
    print(f"Triggering {workflow_id_or_file} on ref '{ref}'...")
    api_request(url, method="POST", data={"ref": ref})
    print("Dispatched successfully.")

if __name__ == '__main__':
    workflows = list_workflows()
    if len(sys.argv) > 1 and sys.argv[1] == '--dispatch':
        ref = sys.argv[2] if len(sys.argv) > 2 else "feat/connectors-bounty"
        trigger_workflow("nightly_full_suite.yml", ref=ref)

