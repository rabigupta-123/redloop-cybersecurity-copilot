# OSINT Platform Signature Drift Status Report (Phase M.2)

- **Generated At**: `2026-11-11T10:20:22.254221+00:00`
- **Platforms Checked**: `113` (`28` email + `85` username)
- **Canary Probes per Platform**: `2 known-true + 2 known-false (4 total)`
- **Total Probe Evaluations**: `450 / 452` (`99.56%`, Wilson 95% CI: `[0.9840, 0.9988]`)
- **Overall Drift Status**: **`DRIFT_DETECTED`** (`2` platform(s) flagged)

## Flagged Platforms (`DRIFT_ALERT`)

| Module | Platform ID | Platform Name | Probes Correct | Accuracy | Wilson 95% CI | Root Cause / Upstream Change |
|---|---|---|---:|---:|---|---|
| `email_footprint` | **`vimeo`** | Vimeo | `3/4` | `0.7500` | `[0.3006, 0.9544]` | Vimeo /join endpoint deployed Cloudflare Turnstile HTTP 403 challenge on unauthenticated email availability probes, suppressing SSR exists token. |
| `username_footprint` | **`patreon`** | Patreon | `3/4` | `0.7500` | `[0.3006, 0.9544]` | Patreon creator profile migrated to Next.js CSR hydration shell; SSR response omitted profile body signature (FN -> UNKNOWN on known_true_2). |

## Summary by Module

| Module | Platforms Checked | Healthy (`4/4`) | Flagged (`< 1.00`) |
|---|---:|---:|---:|
| `email_footprint` | `28` | `27` | `1` |
| `username_footprint` | `85` | `84` | `1` |
