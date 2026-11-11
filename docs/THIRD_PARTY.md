# Third-Party Services & License Isolation Manifest (`docs/THIRD_PARTY.md`)

**REDLOOP Core License**: `MIT` (Copyright (c) 2026 Rabi Kumar Gupta — see [`LICENSE`](../LICENSE)).

To preserve strict MIT license purity across the REDLOOP codebase, third-party tools governed by copyleft licenses (such as `GPL-3.0`) or external system distributions are **never** copied, vendored, statically linked, or embedded into REDLOOP source files. Instead, they execute as **isolated, out-of-process services** accessed exclusively via network/IPC connectors (`REST`, `SSH`, or `MCP`).

---

## 1. SpiderFoot (OSINT Automation Service — Gate L.4)

| Attribute | Details |
| :--- | :--- |
| **Name** | SpiderFoot |
| **License** | **GNU General Public License v3.0 (`GPL-3.0`)** |
| **Upstream URL** | [`https://github.com/smicallef/spiderfoot`](https://github.com/smicallef/spiderfoot) |
| **Deployment Mode** | Isolated Docker Container (`spiderfoot:latest` / `ghcr.io/smicallef/spiderfoot` listening on `127.0.0.1:5001`) |
| **Integration Mechanism** | Out-of-process HTTP REST API Connector (`src/redloop/connectors/spiderfoot_connector.py`) registered in `ConnectorRegistry` (`builtin-spiderfoot`). Zero SpiderFoot source code is included in this repository. |
| **Data Boundary** | REDLOOP submits authorized scan targets via `POST /startscan`, polls status via `GET /scanstatus`, retrieves JSON event rows via `POST /scaneventresults`, Sanitizes untrusted output, and maps events into REDLOOP `Evidence` and `Finding` records with cryptographic `evidence_id` references. |

### Running the Isolated SpiderFoot Service via Docker
```bash
docker run -d --name redloop-spiderfoot \
  -p 127.0.0.1:5001:5001 \
  --security-opt no-new-privileges:true \
  ghcr.io/smicallef/spiderfoot:latest
```

---

## 2. Kali Linux Remote Execution Target (Gate L.5)

| Attribute | Details |
| :--- | :--- |
| **Name** | Kali Linux Rolling (`kalilinux/kali-rolling`) |
| **License** | Various upstream open-source licenses (Debian/GPL/BSD/MIT per package) |
| **Upstream URL** | [`https://www.kali.org/`](https://www.kali.org/) |
| **Deployment Mode** | Remote Kali VM, dedicated Linux host, or isolated Kali Docker container accessed over SSH |
| **Integration Mechanism** | Out-of-process SSH Connector (`src/redloop/connectors/kali_ssh_connector.py`). Local Windows hosts do not bundle native Linux offensive binaries; all commands pass through `ValidatedCommand` + `AssessmentScopeGuard` + `KaliCopilot` cached `--help` flag verification before SSH dispatch. |

---

## 3. Reverse Engineering Tooling: Radare2 & Ghidra Headless (Gate L.6)

| Attribute | Details |
| :--- | :--- |
| **Name** | Radare2 (`r2` / `r2pipe`) & NSA Ghidra Headless Analyzer |
| **License** | Radare2: `LGPL-3.0` / Ghidra: `Apache-2.0` |
| **Upstream URLs** | [`https://github.com/radareorg/radare2`](https://github.com/radareorg/radare2) · [`https://github.com/NationalSecurityAgency/ghidra`](https://github.com/NationalSecurityAgency/ghidra) |
| **Deployment Mode** | Isolated air-gapped analysis container (`--network none`) operating strictly on operator-uploaded binary artifacts |
| **Integration Mechanism** | Out-of-process CLI / `r2pipe` JSON IPC connector (`src/redloop/connectors/re_connector.py`). Never invoked against network targets. |

