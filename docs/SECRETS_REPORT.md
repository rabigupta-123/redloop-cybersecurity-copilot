# REDLOOP — Secrets Hygiene and Audit Report

## Summary
- Total potential secret indicators identified: 8
- Policy: Zero hardcoded production secrets in tracked source files or public commit history.
- Environment variables must be loaded via `os.environ` or `.env` (gitignored).

## Findings and Remediation
| Location | Type | Masked Indicator | Remediation / Recommendation |
|---|---|---|---|
| `scope.yaml` | 64-Hex String | `2aed...2740` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |
| `git_commit_history` | Groq API Key | `gsk_...uBgG` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |
| `git_commit_history` | Groq API Key | `gsk_...7890` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |
| `git_commit_history` | Groq API Key | `gsk_...3456` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |
| `git_commit_history` | Groq API Key | `gsk_...yz99` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |
| `git_commit_history` | OpenAI API Key | `sk-a...alue` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |
| `git_commit_history` | OpenAI API Key | `sk-a...3456` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |
| `git_commit_history` | Anthropic API Key | `sk-a...alue` | Revoke immediately at provider portal and rotate secret. Do not rewrite public history. |

## Recommended Rotation Procedures
1. **Scope HMAC Secret:** Execute `redloop scope rotate-secret` to re-sign active scope contracts.
2. **LLM Provider Keys (Groq / OpenAI / Anthropic / Google):** Reissue tokens at provider console and update local `.env`.
3. **VirusTotal & Shodan Keys:** Reissue in account dashboard and store in local environment variables.
4. **Operator Capability Tokens:** Rotate via `redloop operator-token --generate`.

## .gitignore Verification
- `.env` and `.env.*` (excluding `.env.example`): IGNORED
- `*.key` and cryptographic secret sidecars: IGNORED
- `data/` and local SQLite databases: IGNORED
- `logs/` and runtime logs: IGNORED
- `artifacts/`: IGNORED
