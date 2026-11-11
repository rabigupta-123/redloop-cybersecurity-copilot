# OSINT Platform Signature Drift Status Report (Phase M.2)

- **Generated At**: `2026-11-11T09:30:19.479246+00:00`
- **Platforms Checked**: `113` (`28` email + `85` username)
- **Canary Probes per Platform**: `2 known-true + 2 known-false (4 total)`
- **Total Probe Evaluations**: `448 / 452` (`99.12%`, Wilson 95% CI: `[0.9775, 0.9966]`)
- **Overall Drift Status**: **`DRIFT_DETECTED`** (`4` platform(s) flagged)

## Flagged Platforms (`DRIFT_ALERT`)

| Module | Platform ID | Platform Name | Probes Correct | Accuracy | Wilson 95% CI | Root Cause / Upstream Change |
|---|---|---|---:|---:|---|---|
| `email_footprint` | **`bitbucket`** | Bitbucket | `3/4` | `0.7500` | `[0.3006, 0.9544]` | Bitbucket signup response changed available-email wording from 'available' to 'free_to_register' while including 'taken' in tooltip help copy (FP on known_false_2). |
| `email_footprint` | **`vimeo`** | Vimeo | `3/4` | `0.7500` | `[0.3006, 0.9544]` | Vimeo /join endpoint deployed Cloudflare Turnstile HTTP 403 challenge on unauthenticated email availability probes, suppressing SSR exists token. |
| `username_footprint` | **`medium`** | Medium | `3/4` | `0.7500` | `[0.3006, 0.9544]` | Medium deleted-user edge page returned soft-200 HTML shell containing 'medium.com' header signature without legacy '404' marker (FP on known_false_2). |
| `username_footprint` | **`patreon`** | Patreon | `3/4` | `0.7500` | `[0.3006, 0.9544]` | Patreon creator profile migrated to Next.js CSR hydration shell; SSR response omitted profile body signature (FN -> UNKNOWN on known_true_2). |

## Summary by Module

| Module | Platforms Checked | Healthy (`4/4`) | Flagged (`< 1.00`) |
|---|---:|---:|---:|
| `email_footprint` | `28` | `26` | `2` |
| `username_footprint` | `85` | `83` | `2` |
