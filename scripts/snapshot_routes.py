"""Snapshot routes of REDLOOP application."""
from __future__ import annotations

import json
from pathlib import Path
from redloop.unified_app import get_app

def main():
    app = get_app()
    routes = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path and methods:
            for method in sorted(methods):
                if method not in ("HEAD", "OPTIONS"):
                    routes.append({"method": method, "path": path})
        elif path:
            routes.append({"method": "GET", "path": path})

    # Sort deterministically
    routes = sorted(routes, key=lambda r: (r["path"], r["method"]))
    out_file = Path("artifacts/routes_before.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(routes, f, indent=2)
    print(f"Snapshotted {len(routes)} routes to {out_file}")

if __name__ == "__main__":
    main()

