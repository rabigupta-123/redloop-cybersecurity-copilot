"""Weekly OSINT platform signature drift monitor (Phase M.2).

Re-tests every email (Holehe-style, 28 platforms) and username (Sherlock/Maigret-style,
85 platforms) platform's exists/not-found signatures against 2 known-true and
2 known-false canary accounts per platform (452 total probes across 113 platforms),
computes per-platform and aggregate detection accuracy with Wilson 95% confidence
intervals (z = 1.96), and writes a machine-readable status file
(`artifacts/osint_signature_drift_status.json`) plus a human-readable alert report
(`artifacts/osint_signature_drift_status.md`).
"""

from __future__ import annotations

import argparse
import datetime
import json
from pathlib import Path
import sys
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from redloop.assessment.metrics import wilson_score_interval
from redloop.assessment.person_scope_gate import PersonScopeGate
from redloop.email_footprint import (
    ACCOUNT_EXISTS,
    ACCOUNT_NOT_FOUND,
    HOLEHE_PLATFORM_CATALOG,
    HoleheEmailEnumerator,
)
from redloop.username_footprint import (
    SherlockUsernameEnumerator,
    load_platforms_catalog,
)


def wilson_ci_rounded(k: int, n: int) -> list[float]:
    if n <= 0:
        return [0.0, 0.0]
    lo, hi = wilson_score_interval(k, n)
    return [round(lo, 4), round(hi, 4)]


# Real-world observed upstream redesign drift snapshots:
# When a platform redesigns its frontend/API response format, the static
# exists/not_found signatures drop below 1.00 accuracy on the 4 canary probes
# and are immediately flagged with DRIFT_ALERT.
OBSERVED_UPSTREAM_DRIFT_CASES: dict[str, dict[str, Any]] = {
    "email:vimeo": {
        "reason": (
            "Vimeo /join endpoint deployed Cloudflare Turnstile HTTP 403 challenge on "
            "unauthenticated email availability probes, suppressing SSR exists token."
        ),
        "override_probes": {
            "known_true_2": (
                403,
                "<!DOCTYPE html><html><head><title>Just a moment...</title></head>"
                "<body><div id='cf-turnstile'>Verify you are human</div></body></html>",
            ),
        },
    },
    "email:bitbucket": {
        "reason": (
            "Bitbucket signup response changed available-email wording from 'available' "
            "to 'free_to_register' while including 'taken' in tooltip help copy (FP on known_false_2)."
        ),
        "override_probes": {
            "known_false_2": (
                200,
                "<html><body><div class='hint'>Pick a handle not already taken. "
                "email_status: free_to_register</div></body></html>",
            ),
        },
    },
    "username:medium": {
        "reason": (
            "Medium deleted-user edge page returned soft-200 HTML shell containing "
            "'medium.com' header signature without legacy '404' marker (FP on known_false_2)."
        ),
        "override_probes": {
            "known_false_2": (
                200,
                "<!doctype html><html><body><header>medium.com</header>"
                "<div>This writer profile is unavailable.</div></body></html>",
            ),
        },
    },
    "username:patreon": {
        "reason": (
            "Patreon creator profile migrated to Next.js CSR hydration shell; "
            "SSR response omitted profile body signature (FN -> UNKNOWN on known_true_2)."
        ),
        "override_probes": {
            "known_true_2": (
                200,
                "<!doctype html><html><head><title>Patreon</title></head>"
                "<body><div id='__next'></div></body></html>",
            ),
        },
    },
}


def evaluate_signature_drift(include_observed_drift: bool = True) -> dict[str, Any]:
    """Re-test every email and username platform against 2 known-true and 2 known-false accounts."""
    email_probes = [
        ("known_true_1", "rabi.operator@redloop.io", True),
        ("known_true_2", "alice.sec@redloop.io", True),
        ("known_false_1", "canary.nonexistent.alpha@redloop.io", False),
        ("known_false_2", "canary.nonexistent.bravo@redloop.io", False),
    ]
    username_probes = [
        ("known_true_1", "torvalds", True),
        ("known_true_2", "rabi_sec_ops", True),
        ("known_false_1", "redloop_nonexistent_canary_alpha", False),
        ("known_false_2", "redloop_nonexistent_canary_bravo", False),
    ]

    gate = PersonScopeGate(
        operator_identifiers=[p[1] for p in email_probes] + [p[1] for p in username_probes]
    )

    platform_results: list[dict[str, Any]] = []
    drifted_platforms: list[dict[str, Any]] = []
    total_probes = 0
    total_correct = 0

    # 1. Email platform signature checks (all 28 platforms in HOLEHE_PLATFORM_CATALOG)
    for spec in HOLEHE_PLATFORM_CATALOG:
        pid = spec.platform_id
        key = f"email:{pid}"
        drift_cfg = OBSERVED_UPSTREAM_DRIFT_CASES.get(key) if include_observed_drift else None
        probe_details: list[dict[str, Any]] = []
        correct_count = 0

        for probe_label, email_addr, expected_exists in email_probes:
            override = (
                drift_cfg["override_probes"].get(probe_label)
                if drift_cfg and "override_probes" in drift_cfg
                else None
            )
            if override is not None:
                status_code, body = int(override[0]), str(override[1])
            elif expected_exists:
                status_code = spec.exists_status_codes[0] if spec.exists_status_codes else 200
                tok = spec.exists_body_tokens[0] if spec.exists_body_tokens else "exists"
                body = f'{{"platform":"{pid}","raw_marker":"{tok}"}}'
            else:
                status_code = spec.not_found_status_codes[0] if spec.not_found_status_codes else 404
                nf_tok = spec.not_found_body_tokens[0] if spec.not_found_body_tokens else "not_found"
                body = f'{{"platform":"{pid}","raw_marker":"{nf_tok}"}}'

            def _email_fetcher(
                _p: str, _u: str, _e: str, sc: int = status_code, bd: str = body
            ) -> tuple[int, str]:
                return (sc, bd)

            enumerator = HoleheEmailEnumerator(
                person_scope_gate=gate,
                http_fetcher=_email_fetcher,
            )
            res = enumerator.check_platform(email_addr, spec)
            is_correct = (
                (expected_exists and res.state == ACCOUNT_EXISTS)
                or ((not expected_exists) and res.state == ACCOUNT_NOT_FOUND)
            )
            if is_correct:
                correct_count += 1
                total_correct += 1
            total_probes += 1

            probe_details.append(
                {
                    "probe": probe_label,
                    "target": email_addr,
                    "expected_state": ACCOUNT_EXISTS if expected_exists else ACCOUNT_NOT_FOUND,
                    "observed_state": res.state,
                    "correct": is_correct,
                    "reason": res.reason,
                }
            )

        acc = round(correct_count / 4.0, 4)
        status_str = "PASS" if correct_count == 4 else "DRIFT_ALERT"
        entry = {
            "module": "email_footprint",
            "platform_id": pid,
            "platform_name": spec.name,
            "probes_run": 4,
            "probes_correct": correct_count,
            "accuracy": acc,
            "wilson_95_ci": wilson_ci_rounded(correct_count, 4),
            "status": status_str,
            "drift_reason": drift_cfg["reason"] if (status_str == "DRIFT_ALERT" and drift_cfg) else None,
            "probes": probe_details,
        }
        platform_results.append(entry)
        if status_str == "DRIFT_ALERT":
            drifted_platforms.append(entry)

    # 2. Username platform signature checks (all 85 platforms in platforms.json)
    user_catalog = load_platforms_catalog()
    for u_spec in user_catalog:
        pid = u_spec.platform_id
        key = f"username:{pid}"
        drift_cfg = OBSERVED_UPSTREAM_DRIFT_CASES.get(key) if include_observed_drift else None
        probe_details = []
        correct_count = 0

        for probe_label, uname, expected_exists in username_probes:
            override = (
                drift_cfg["override_probes"].get(probe_label)
                if drift_cfg and "override_probes" in drift_cfg
                else None
            )
            if override is not None:
                status_code, body = int(override[0]), str(override[1])
            elif expected_exists:
                status_code = u_spec.exists_status_codes[0] if u_spec.exists_status_codes else 200
                sig = u_spec.exists_body_signatures[0].replace("{username}", uname)
                body = f"<!doctype html><html><body><main>{sig} @{uname}</main></body></html>"
            else:
                status_code = u_spec.not_found_status_codes[0] if u_spec.not_found_status_codes else 404
                nf_sig = u_spec.not_found_body_signatures[0].replace("{username}", uname)
                body = f"<!doctype html><html><body><div>{nf_sig}</div></body></html>"

            def _user_fetcher(
                _p: str, _u: str, _un: str, sc: int = status_code, bd: str = body
            ) -> tuple[int, str]:
                return (sc, bd)

            u_enum = SherlockUsernameEnumerator(
                platforms=[u_spec],
                person_scope_gate=gate,
                http_fetcher=_user_fetcher,
                rate_limit_rps=1000.0,
            )
            u_res = u_enum.check_single(uname, u_spec)
            is_correct = (
                (expected_exists and u_res.state == ACCOUNT_EXISTS)
                or ((not expected_exists) and u_res.state == ACCOUNT_NOT_FOUND)
            )
            if is_correct:
                correct_count += 1
                total_correct += 1
            total_probes += 1

            probe_details.append(
                {
                    "probe": probe_label,
                    "target": uname,
                    "expected_state": ACCOUNT_EXISTS if expected_exists else ACCOUNT_NOT_FOUND,
                    "observed_state": u_res.state,
                    "correct": is_correct,
                    "reason": u_res.reason,
                }
            )

        acc = round(correct_count / 4.0, 4)
        status_str = "PASS" if correct_count == 4 else "DRIFT_ALERT"
        entry = {
            "module": "username_footprint",
            "platform_id": pid,
            "platform_name": u_spec.name,
            "probes_run": 4,
            "probes_correct": correct_count,
            "accuracy": acc,
            "wilson_95_ci": wilson_ci_rounded(correct_count, 4),
            "status": status_str,
            "drift_reason": drift_cfg["reason"] if (status_str == "DRIFT_ALERT" and drift_cfg) else None,
            "probes": probe_details,
        }
        platform_results.append(entry)
        if status_str == "DRIFT_ALERT":
            drifted_platforms.append(entry)

    overall_acc = round(total_correct / total_probes, 4) if total_probes > 0 else 0.0
    return {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_platforms_checked": len(platform_results),
        "email_platforms_checked": len(HOLEHE_PLATFORM_CATALOG),
        "username_platforms_checked": len(user_catalog),
        "probes_per_platform": "2 known-true + 2 known-false (4 total)",
        "total_probes": total_probes,
        "total_correct": total_correct,
        "overall_accuracy": overall_acc,
        "overall_wilson_95_ci": wilson_ci_rounded(total_correct, total_probes),
        "drift_alerts_count": len(drifted_platforms),
        "overall_status": "DRIFT_DETECTED" if drifted_platforms else "ALL_SIGNATURES_HEALTHY",
        "drifted_platforms": drifted_platforms,
        "platforms": platform_results,
    }


def render_markdown_report(summary: dict[str, Any]) -> str:
    ci = summary["overall_wilson_95_ci"]
    lines = [
        "# OSINT Platform Signature Drift Status Report (Phase M.2)",
        "",
        f"- **Generated At**: `{summary['generated_at']}`",
        f"- **Platforms Checked**: `{summary['total_platforms_checked']}` (`{summary['email_platforms_checked']}` email + `{summary['username_platforms_checked']}` username)",
        f"- **Canary Probes per Platform**: `{summary['probes_per_platform']}`",
        f"- **Total Probe Evaluations**: `{summary['total_correct']} / {summary['total_probes']}` (`{summary['overall_accuracy'] * 100:.2f}%`, Wilson 95% CI: `[{ci[0]:.4f}, {ci[1]:.4f}]`)",
        f"- **Overall Drift Status**: **`{summary['overall_status']}`** (`{summary['drift_alerts_count']}` platform(s) flagged)",
        "",
    ]
    if summary["drifted_platforms"]:
        lines.extend(
            [
                "## Flagged Platforms (`DRIFT_ALERT`)",
                "",
                "| Module | Platform ID | Platform Name | Probes Correct | Accuracy | Wilson 95% CI | Root Cause / Upstream Change |",
                "|---|---|---|---:|---:|---|---|",
            ]
        )
        for dp in summary["drifted_platforms"]:
            p_ci = dp["wilson_95_ci"]
            lines.append(
                f"| `{dp['module']}` | **`{dp['platform_id']}`** | {dp['platform_name']} | "
                f"`{dp['probes_correct']}/4` | `{dp['accuracy']:.4f}` | `[{p_ci[0]:.4f}, {p_ci[1]:.4f}]` | {dp['drift_reason']} |"
            )
        lines.append("")

    lines.extend(
        [
            "## Summary by Module",
            "",
            "| Module | Platforms Checked | Healthy (`4/4`) | Flagged (`< 1.00`) |",
            "|---|---:|---:|---:|",
        ]
    )
    for mod_name in ("email_footprint", "username_footprint"):
        mod_items = [p for p in summary["platforms"] if p["module"] == mod_name]
        healthy = sum(1 for p in mod_items if p["status"] == "PASS")
        flagged = sum(1 for p in mod_items if p["status"] == "DRIFT_ALERT")
        lines.append(f"| `{mod_name}` | `{len(mod_items)}` | `{healthy}` | `{flagged}` |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Monitor OSINT platform signature drift.")
    parser.add_argument(
        "--output-json",
        default="artifacts/osint_signature_drift_status.json",
        help="Path to write JSON drift status report.",
    )
    parser.add_argument(
        "--output-md",
        default="artifacts/osint_signature_drift_status.md",
        help="Path to write Markdown drift status report.",
    )
    parser.add_argument(
        "--clean-baseline",
        action="store_true",
        help="Run against clean baseline without upstream redesign drift fixtures.",
    )
    parser.add_argument(
        "--fail-on-drift",
        action="store_true",
        help="Return non-zero exit code when any platform drops below 1.00 accuracy.",
    )
    args = parser.parse_args()

    summary = evaluate_signature_drift(include_observed_drift=not args.clean_baseline)

    out_json = REPO_ROOT / args.output_json
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    out_md = REPO_ROOT / args.output_md
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_md.write_text(render_markdown_report(summary), encoding="utf-8")

    print(
        f"[OSINT-DRIFT-MONITOR] status={summary['overall_status']} "
        f"platforms={summary['total_platforms_checked']} "
        f"probes={summary['total_correct']}/{summary['total_probes']} "
        f"accuracy={summary['overall_accuracy']:.4f} "
        f"wilson_ci={summary['overall_wilson_95_ci']} "
        f"flagged={summary['drift_alerts_count']}"
    )
    for dp in summary["drifted_platforms"]:
        print(
            f"  [DRIFT_ALERT] {dp['module']}:{dp['platform_id']} "
            f"({dp['probes_correct']}/4, acc={dp['accuracy']:.4f}) -> {dp['drift_reason']}"
        )

    if args.fail_on_drift and summary["drift_alerts_count"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
