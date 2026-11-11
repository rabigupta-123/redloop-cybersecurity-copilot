import urllib.request
import json
import os
import sys

def list_releases():
    req = urllib.request.Request(
        'https://api.github.com/repos/rabigupta-123/redloop-cybersecurity-copilot/releases',
        headers={'User-Agent': 'Mozilla/5.0'}
    )
    with urllib.request.urlopen(req) as resp:
        releases = json.loads(resp.read().decode())
        for r in releases:
            print(f"Release ID: {r['id']}, tag_name: {r['tag_name']}, name: {r['name']}")

if __name__ == '__main__':
    list_releases()
