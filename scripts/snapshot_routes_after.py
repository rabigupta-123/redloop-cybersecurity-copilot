"""Snapshot routes after all phases and assert zero deletions."""
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

    routes = sorted(routes, key=lambda r: (r["path"], r["method"]))
    out_file = Path("artifacts/routes_after.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(routes, f, indent=2)
    print(f"Snapshotted {len(routes)} routes to {out_file}")

    # Load before
    before_file = Path("artifacts/routes_before.json")
    with open(before_file, "r", encoding="utf-8") as f:
        before = json.load(f)

    before_set = {(r["method"], r["path"]) for r in before}
    after_set = {(r["method"], r["path"]) for r in routes}

    deleted = before_set - after_set
    added = after_set - before_set

    print(f"Routes before: {len(before_set)}, Routes after: {len(after_set)}")
    print(f"Deleted routes: {len(deleted)}, Added routes: {len(added)}")

    assert len(deleted) == 0, f"Routes were deleted: {deleted}"
    print("ROUTE STABILITY CHECK: PASSED (0 deleted routes)")

if __name__ == "__main__":
    main()

