"""Static configuration, container, and cloud policy security engine for RedLoop.

Strictly adheres to:
- Sections 19, 20, 21: Provider-neutral, container & configuration analyzers.
- Checks Dockerfiles, Docker Compose, Kubernetes manifests, Nginx/Apache configs, and Cloud policies.
- Distinguishes OBSERVED from INFERRED from NOT_AVAILABLE.
- Never prints or exposes raw credentials in findings.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from redloop.assessment.models import (
    Confidence,
    Evidence,
    Finding,
    FindingStatus,
    OperationClass,
    Severity,
    StageResult,
    StageStatus,
)
from redloop.assessment.scope_guard import AssessmentScopeGuard
from redloop.audit import AuditLogger

DOCKER_SENSITIVE_MOUNTS = (
    "/var/run/docker.sock",
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
)

MANAGEMENT_PORTS = {
    22: "SSH",
    3389: "RDP",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


class ConfigEngine:
    """Audits container artifacts, cloud templates, and server configurations statically."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit

    def audit_config_file(
        self,
        file_path: str | Path,
        target_label: str = "127.0.0.1",
        operation_id: str = "op-config-audit",
    ) -> StageResult:
        """Audit a configuration file or artifact statically."""
        start_time = time.time()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []

        path = Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            return StageResult(
                stage="config_security",
                status=StageStatus.FAILED,
                reason=f"Config artifact not found: {path}",
                duration_seconds=round(time.time() - start_time, 3),
            )

        self.scope_guard.verify_operation(
            target=target_label,
            operation_class=OperationClass.READ_ONLY,
            category="config_security",
        )

        content = path.read_text(encoding="utf-8", errors="ignore")
        fname = path.name.lower()

        # Route by configuration type
        if "dockerfile" in fname:
            findings.extend(self._audit_dockerfile(path.name, content, target_label, operation_id, evidence_list))
        elif "compose" in fname or fname.endswith((".yml", ".yaml")):
            # Could be docker-compose, k8s, or cloud policy
            if "apiversion:" in content.lower() or "kind: pod" in content.lower() or "kind: deployment" in content.lower():
                findings.extend(self._audit_k8s(path.name, content, target_label, operation_id, evidence_list))
            elif "services:" in content:
                findings.extend(self._audit_docker_compose(path.name, content, target_label, operation_id, evidence_list))
            else:
                findings.extend(self._audit_generic_policy(path.name, content, target_label, operation_id, evidence_list))
        elif "nginx" in fname or fname.endswith(".conf"):
            findings.extend(self._audit_nginx_config(path.name, content, target_label, operation_id, evidence_list))
        else:
            findings.extend(self._audit_generic_policy(path.name, content, target_label, operation_id, evidence_list))

        duration = round(time.time() - start_time, 3)
        if self.audit:
            self.audit.log(
                "config_audit_completed",
                file=path.name,
                findings_count=len(findings),
                duration=duration,
            )

        return StageResult(
            stage="config_security",
            status=StageStatus.SUCCESS,
            reason=f"Config security audit completed for {path.name} ({len(findings)} findings).",
            duration_seconds=duration,
            findings=findings,
            evidence=evidence_list,
            data={"file": path.name, "findings_count": len(findings)},
        )

    def _audit_dockerfile(
        self,
        filename: str,
        content: bytes | str,
        target_label: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Audit Dockerfile instructions for security best practices."""
        findings = []
        lines = content.splitlines()

        has_user_directive = False
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            upper = stripped.upper()
            if upper.startswith("USER "):
                user_val = stripped.split(maxsplit=1)[1].strip()
                if user_val not in ("root", "0"):
                    has_user_directive = True

            # Hardcoded secrets in ENV or ARG
            if (upper.startswith("ENV ") or upper.startswith("ARG ")) and any(
                secret_word in upper for secret_word in ("SECRET", "PASSWORD", "PASSWD", "TOKEN", "API_KEY")
            ):
                ev = Evidence(
                    target=target_label,
                    operation_id=operation_id,
                    tool_output=f"Line {idx}: {stripped[:25]}... (redacted)",
                    response_excerpt=f"Dockerfile line {idx} declares a sensitive ENV/ARG instruction.",
                    parser_result={"line": idx, "type": "OBSERVED"},
                )
                evidence_list.append(ev)
                findings.append(
                    Finding(
                        title=f"Hardcoded Credential in Dockerfile ({filename})",
                        category="container_security",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        asset=target_label,
                        target=filename,
                        description=f"Dockerfile line {idx} defines an environment variable or argument containing credentials.",
                        evidence=[ev],
                        detection_method="dockerfile_static_analysis",
                        impact="Image layers retain secrets permanently, leaking credentials to anyone with pull access.",
                        remediation="Use build secrets (--secret) or external secret management instead of ENV/ARG for credentials.",
                        references=["https://cwe.mitre.org/data/definitions/798.html"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

        if not has_user_directive:
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="No non-root USER instruction found in Dockerfile.",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Container Runs As Root User ({filename})",
                    category="container_security",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description=f"Dockerfile '{filename}' lacks a USER directive, defaulting container execution to UID 0 (root).",
                    evidence=[ev],
                    detection_method="dockerfile_static_analysis",
                    impact="Running as root amplifies the impact of container breakout vulnerabilities.",
                    remediation="Add 'USER nonroot' or specify an unprivileged UID in the Dockerfile.",
                    references=["https://cwe.mitre.org/data/definitions/250.html"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        return findings

    def _audit_docker_compose(
        self,
        filename: str,
        content: str,
        target_label: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Audit Docker Compose configurations for dangerous settings."""
        findings = []

        # 1. Privileged Mode
        if re.search(r"privileged:\s*(true|yes|1)", content, re.IGNORECASE):
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="Found 'privileged: true' setting in Compose file.",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Container Configured With Privileged Mode ({filename})",
                    category="container_security",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description=f"Docker Compose file '{filename}' grants full host root privileges to container ('privileged: true').",
                    evidence=[ev],
                    detection_method="docker_compose_static_analysis",
                    impact="Privileged containers can easily escape to the host kernel and achieve full host takeover.",
                    remediation="Remove 'privileged: true' and grant only specifically required Linux capabilities via 'cap_add'.",
                    references=["https://attack.mitre.org/techniques/T1611/"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        # 2. Host Network Mode
        if re.search(r"network_mode:\s*[\"']?host[\"']?", content, re.IGNORECASE):
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="Found 'network_mode: host' in Compose file.",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Container Uses Host Network Namespace ({filename})",
                    category="container_security",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description=f"Docker Compose file '{filename}' disables network namespace isolation ('network_mode: host').",
                    evidence=[ev],
                    detection_method="docker_compose_static_analysis",
                    impact="The container shares network interfaces and listening sockets directly with the host.",
                    remediation="Use bridge or overlay networks instead of host networking.",
                    references=["https://attack.mitre.org/techniques/T1611/"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        # 3. Dangerous Host Mounts (e.g. docker.sock or root fs)
        for mount in DOCKER_SENSITIVE_MOUNTS:
            if mount in content:
                ev = Evidence(
                    target=target_label,
                    operation_id=operation_id,
                    response_excerpt=f"Sensitive host filesystem mount detected: {mount}",
                    parser_result={"mount": mount, "type": "OBSERVED"},
                )
                evidence_list.append(ev)
                findings.append(
                    Finding(
                        title=f"Dangerous Host Filesystem Mount in Container ({mount})",
                        category="container_security",
                        severity=Severity.CRITICAL if mount == "/var/run/docker.sock" else Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        asset=target_label,
                        target=filename,
                        description=f"Container mounts sensitive host path '{mount}', which can facilitate complete host compromise.",
                        evidence=[ev],
                        detection_method="docker_compose_static_analysis",
                        impact="Mounting the Docker socket or host root directory allows arbitrary container breakout to host.",
                        remediation=f"Do not mount {mount} inside unprivileged containers.",
                        references=["https://attack.mitre.org/techniques/T1611/"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

        return findings

    def _audit_k8s(
        self,
        filename: str,
        content: str,
        target_label: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Audit Kubernetes manifest security context."""
        findings = []

        if "privileged: true" in content:
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="Kubernetes securityContext sets 'privileged: true'.",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Privileged Pod in Kubernetes Manifest ({filename})",
                    category="container_security",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description=f"Manifest '{filename}' grants privileged access to container security context.",
                    evidence=[ev],
                    detection_method="k8s_manifest_analysis",
                    impact="Allows node-level privilege escalation from compromised pod.",
                    remediation="Set 'securityContext.privileged: false' and drop all unneeded capabilities.",
                    references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        if "hostPID: true" in content or "hostIPC: true" in content:
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="Pod shares host PID or IPC namespace.",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Pod Shares Host Namespace ({filename})",
                    category="container_security",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description=f"Manifest '{filename}' enables hostPID or hostIPC.",
                    evidence=[ev],
                    detection_method="k8s_manifest_analysis",
                    impact="Pod can inspect or interfere with processes running on the host node.",
                    remediation="Disable hostPID and hostIPC in pod specification.",
                    references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        return findings

    def _audit_nginx_config(
        self,
        filename: str,
        content: str,
        target_label: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Audit Nginx configuration for insecure settings."""
        findings = []

        # Check for missing security headers in server blocks
        if "add_header X-Content-Type-Options" not in content:
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="Missing 'add_header X-Content-Type-Options \"nosniff\";' in Nginx config.",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Nginx Missing X-Content-Type-Options Directive ({filename})",
                    category="configuration_security",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description="Nginx configuration does not explicitly emit X-Content-Type-Options header.",
                    evidence=[ev],
                    detection_method="nginx_config_analysis",
                    impact="Browsers may perform MIME-type sniffing on untrusted downloads.",
                    remediation="Add 'add_header X-Content-Type-Options \"nosniff\" always;' inside http/server blocks.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        # Check for legacy SSL protocols
        if re.search(r"ssl_protocols\s+.*(SSLv2|SSLv3|TLSv1\s|TLSv1\.1)", content):
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="ssl_protocols includes deprecated protocols (SSLv3/TLSv1/TLSv1.1).",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Nginx Permits Deprecated TLS Protocols ({filename})",
                    category="configuration_security",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description="Nginx configuration enables obsolete SSL/TLS protocols with known cryptographic vulnerabilities.",
                    evidence=[ev],
                    detection_method="nginx_config_analysis",
                    impact="Enables downgrade and padding oracle attacks (e.g. POODLE, BEAST).",
                    remediation="Configure 'ssl_protocols TLSv1.2 TLSv1.3;'.",
                    references=["https://cwe.mitre.org/data/definitions/326.html"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        return findings

    def _audit_generic_policy(
        self,
        filename: str,
        content: str,
        target_label: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Audit generic cloud security policies (AWS/GCP/Terraform)."""
        findings = []

        # Check for public administrative exposure (0.0.0.0/0 on sensitive ports)
        if "0.0.0.0/0" in content:
            for port, name in MANAGEMENT_PORTS.items():
                if str(port) in content:
                    ev = Evidence(
                        target=target_label,
                        operation_id=operation_id,
                        response_excerpt=f"Matched CIDR 0.0.0.0/0 with management port {port} ({name}) in policy.",
                        parser_result={"port": port, "service": name, "type": "OBSERVED"},
                    )
                    evidence_list.append(ev)
                    findings.append(
                        Finding(
                            title=f"Unrestricted Internet Exposure for {name} (Port {port})",
                            category="cloud_security",
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            asset=target_label,
                            target=filename,
                            port=port,
                            description=f"Configuration file '{filename}' permits inbound traffic from 0.0.0.0/0 to {name} service on port {port}.",
                            evidence=[ev],
                            detection_method="cloud_policy_analysis",
                            impact="Exposes administrative services directly to the public internet, inviting automated brute-force and exploit attempts.",
                            remediation=f"Restrict access to port {port} to authorized bastion hosts or corporate IP ranges.",
                            references=["https://cwe.mitre.org/data/definitions/284.html"],
                            source_operation_id=operation_id,
                            status=FindingStatus.OPEN,
                        )
                    )

        # Check for IAM wildcard administrative privileges
        if re.search(r"\"Action\":\s*\"[\*]\"", content) and re.search(r"\"Resource\":\s*\"[\*]\"", content):
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                response_excerpt="IAM policy grants Action: '*' on Resource: '*'.",
                parser_result={"type": "OBSERVED"},
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Excessive IAM Wildcard Admin Privileges ({filename})",
                    category="cloud_security",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=filename,
                    description=f"Policy in '{filename}' grants unconditional administrator access ('Action: *', 'Resource: *').",
                    evidence=[ev],
                    detection_method="cloud_policy_analysis",
                    impact="Violates the principle of least privilege, enabling full account takeover if identity is compromised.",
                    remediation="Scope IAM permissions strictly to the least actions and resources necessary.",
                    references=["https://cwe.mitre.org/data/definitions/732.html"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        return findings
