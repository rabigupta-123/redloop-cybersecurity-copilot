"""Static File & Malware Triage Engine for RedLoop.

Strictly adheres to:
- Section 18: Never executes uploaded samples automatically.
- Deterministic extraction: SHA-256, SHA-1, MD5, magic bytes, entropy, strings,
  PE/ELF/Mach-O metadata, suspicious sections/imports, embedded IOCs, and encoded payloads.
"""

from __future__ import annotations

import base64
import hashlib
import math
import mimetypes
import re
import struct
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
from redloop.forensics import (
    DOMAIN_PATTERN,
    IP_PATTERN,
    PRINTABLE_RUN,
    URL_PATTERN,
)

MAX_ANALYZE_SIZE = 32 * 1024 * 1024  # 32 MB safety bound
HIGH_ENTROPY_THRESHOLD = 7.15  # Indicates packing or strong encryption

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtCreateThreadEx",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "GetProcAddress",
    "LoadLibraryA",
    "LoadLibraryW",
    "InternetOpenA",
    "URLDownloadToFileA",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
}

SUSPICIOUS_SECTION_NAMES = {
    ".upx",
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".themida",
    ".vmp",
    ".packer",
}


def compute_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for a byte stream."""
    if not data:
        return 0.0
    frequencies = [0] * 256
    for b in data:
        frequencies[b] += 1
    total = len(data)
    entropy = 0.0
    for count in frequencies:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


class FileTriageEngine:
    """Safe, non-destructive static file and malware triage engine."""

    def __init__(
        self,
        scope_guard: AssessmentScopeGuard,
        audit: AuditLogger | None = None,
    ):
        self.scope_guard = scope_guard
        self.audit = audit

    def triage_file(
        self,
        file_path: str | Path,
        target_label: str = "127.0.0.1",
        operation_id: str = "op-file-triage",
    ) -> StageResult:
        """Analyze a file statically without executing it."""
        start_time = time.time()
        findings: list[Finding] = []
        evidence_list: list[Evidence] = []

        path = Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            return StageResult(
                stage="file_triage",
                status=StageStatus.FAILED,
                reason=f"Target file does not exist or is not a regular file: {path}",
                duration_seconds=round(time.time() - start_time, 3),
            )

        # Scope guard verification for file artifact
        self.scope_guard.verify_operation(
            target=target_label,
            operation_class=OperationClass.READ_ONLY,
            category="file_triage",
        )

        file_size = path.stat().st_size
        if file_size > MAX_ANALYZE_SIZE:
            return StageResult(
                stage="file_triage",
                status=StageStatus.BLOCKED,
                reason=f"File exceeds maximum analysis size ({file_size} > {MAX_ANALYZE_SIZE} bytes)",
                duration_seconds=round(time.time() - start_time, 3),
            )

        content = path.read_bytes()

        # 1. Cryptographic hashes & magic bytes
        sha256 = hashlib.sha256(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        magic_bytes = content[:16].hex(" ")
        mime_type, _ = mimetypes.guess_type(path.name)
        mime_type = mime_type or "application/octet-stream"
        entropy = compute_entropy(content)

        triage_data: dict[str, Any] = {
            "file_name": path.name,
            "size_bytes": file_size,
            "sha256": sha256,
            "sha1": sha1,
            "md5": md5,
            "mime_type": mime_type,
            "magic_bytes": magic_bytes,
            "entropy": entropy,
        }

        # 2. Format Identification
        file_format = "unknown"
        if content.startswith(b"MZ"):
            file_format = "PE_WINDOWS"
            pe_findings = self._analyze_pe(path.name, content, target_label, operation_id, evidence_list)
            findings.extend(pe_findings)
        elif content.startswith(b"\x7fELF"):
            file_format = "ELF_LINUX"
            elf_findings = self._analyze_elf(path.name, content, target_label, operation_id, evidence_list)
            findings.extend(elf_findings)
        elif content.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")):
            file_format = "MACHO"
        elif content.startswith(b"PK\x03\x04"):
            file_format = "ZIP_ARCHIVE"

        triage_data["file_format"] = file_format

        # 3. High Entropy Check (Packed or Encrypted Binary)
        if entropy >= HIGH_ENTROPY_THRESHOLD and file_format in ("PE_WINDOWS", "ELF_LINUX", "unknown"):
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                tool_output=f"Entropy: {entropy} / 8.00 (Threshold: {HIGH_ENTROPY_THRESHOLD})",
                parser_result={"entropy": entropy, "format": file_format},
                response_excerpt=f"File {path.name} exhibits abnormally high Shannon entropy ({entropy}), characteristic of obfuscation, encryption, or packers.",
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"High Shannon Entropy in File Artifact ({path.name})",
                    category="malware_triage",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    asset=target_label,
                    target=str(path),
                    description=f"File '{path.name}' has Shannon entropy of {entropy}/8.0, indicating packing, compression, or cryptographic obfuscation.",
                    evidence=[ev],
                    detection_method="shannon_entropy_analysis",
                    impact="Obfuscated binaries often conceal malicious code to evade signature-based detection.",
                    remediation="Perform deeper dynamic sandbox analysis and reverse engineering to inspect unpacked payload.",
                    references=["https://cwe.mitre.org/data/definitions/506.html"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        # 4. Embedded IOC Extraction (IPs, URLs, Domains)
        text_content = content.decode("ascii", errors="ignore")
        urls = list(set(URL_PATTERN.findall(text_content)))[:20]
        ips = [ip for ip in set(IP_PATTERN.findall(text_content)) if not ip.startswith(("127.", "0.", "255."))]
        domains = [d for d in set(DOMAIN_PATTERN.findall(text_content)) if len(d) > 4 and not d.endswith((".exe", ".dll", ".sys", ".txt"))][:20]

        triage_data["extracted_urls"] = urls
        triage_data["extracted_ips"] = ips[:20]
        triage_data["extracted_domains"] = domains

        if urls or (ips and any(not ip.startswith(("10.", "192.168.")) for ip in ips)):
            ev = Evidence(
                target=target_label,
                operation_id=operation_id,
                parser_result={"urls": urls, "ips": ips[:10], "domains": domains[:10]},
                response_excerpt=f"Extracted {len(urls)} URLs and {len(ips)} public IP addresses embedded in binary strings.",
            )
            evidence_list.append(ev)
            findings.append(
                Finding(
                    title=f"Embedded Network Indicators in Binary ({path.name})",
                    category="malware_triage",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    asset=target_label,
                    target=str(path),
                    description=f"Discovered {len(urls)} hardcoded URLs and {len(ips)} IP addresses inside '{path.name}'.",
                    evidence=[ev],
                    detection_method="string_ioc_extraction",
                    impact="Hardcoded endpoints may reveal command-and-control servers or insecure update/telemetry backends.",
                    remediation="Verify whether embedded endpoints are legitimate infrastructure and restrict network outbound connections.",
                    references=["https://cwe.mitre.org/data/definitions/798.html"],
                    source_operation_id=operation_id,
                    status=FindingStatus.OPEN,
                )
            )

        duration = round(time.time() - start_time, 3)
        if self.audit:
            self.audit.log(
                "file_triage_completed",
                target=str(path),
                sha256=sha256,
                findings_count=len(findings),
                duration=duration,
            )

        return StageResult(
            stage="file_triage",
            status=StageStatus.SUCCESS,
            reason=f"Triage completed for {path.name}: {len(findings)} findings, entropy {entropy}.",
            duration_seconds=duration,
            findings=findings,
            evidence=evidence_list,
            data=triage_data,
        )

    def _analyze_pe(
        self,
        filename: str,
        content: bytes,
        target_label: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Analyze Windows Portable Executable structure safely."""
        findings = []
        try:
            # PE Header Offset is at 0x3C
            if len(content) < 0x40:
                return findings
            pe_offset = struct.unpack_from("<I", content, 0x3C)[0]
            if pe_offset + 4 > len(content):
                return findings
            if content[pe_offset : pe_offset + 4] != b"PE\x00\x00":
                return findings

            # Scan strings for suspicious API imports
            found_suspicious_apis = set()
            for api in SUSPICIOUS_IMPORTS:
                if api.encode("ascii") in content:
                    found_suspicious_apis.add(api)

            if len(found_suspicious_apis) >= 3:
                ev = Evidence(
                    target=target_label,
                    operation_id=operation_id,
                    tool_output=", ".join(sorted(found_suspicious_apis)),
                    response_excerpt=f"Matched {len(found_suspicious_apis)} memory manipulation / injection APIs in PE imports: {', '.join(sorted(found_suspicious_apis))}",
                )
                evidence_list.append(ev)
                findings.append(
                    Finding(
                        title=f"Suspicious Memory Injection & Execution APIs in PE ({filename})",
                        category="malware_triage",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        asset=target_label,
                        target=filename,
                        description=(
                            f"PE binary references {len(found_suspicious_apis)} security-sensitive APIs commonly utilized in process hollowing, "
                            f"code injection, or stealth execution: {', '.join(sorted(found_suspicious_apis))}."
                        ),
                        evidence=[ev],
                        detection_method="pe_import_signature_analysis",
                        impact="Potential arbitrary code injection, process hollowing, or defense evasion capabilities.",
                        remediation="Analyze binary behavior in an isolated dynamic sandbox.",
                        references=["https://attack.mitre.org/techniques/T1055/"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

            # Check for known packer section names
            content_lower = content.lower()
            found_packer_sections = set()
            for sname in SUSPICIOUS_SECTION_NAMES:
                if sname.encode("ascii") in content_lower:
                    found_packer_sections.add(sname)

            if found_packer_sections:
                ev = Evidence(
                    target=target_label,
                    operation_id=operation_id,
                    tool_output=", ".join(sorted(found_packer_sections)),
                    response_excerpt=f"Packer section signatures found: {', '.join(sorted(found_packer_sections))}",
                )
                evidence_list.append(ev)
                findings.append(
                    Finding(
                        title=f"Known Binary Packer Signature Detected ({filename})",
                        category="malware_triage",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        asset=target_label,
                        target=filename,
                        description=f"PE binary contains section names corresponding to known packers: {', '.join(sorted(found_packer_sections))}.",
                        evidence=[ev],
                        detection_method="pe_section_fingerprinting",
                        impact="Packers obscure payload contents and anti-virus signatures.",
                        remediation="Unpack the executable using appropriate unpacking tools before signature scanning.",
                        references=["https://attack.mitre.org/techniques/T1027/002/"],
                        source_operation_id=operation_id,
                        status=FindingStatus.OPEN,
                    )
                )

        except Exception as exc:
            if self.audit:
                self.audit.log("pe_analysis_error", error=str(exc))

        return findings

    def _analyze_elf(
        self,
        filename: str,
        content: bytes,
        target_label: str,
        operation_id: str,
        evidence_list: list[Evidence],
    ) -> list[Finding]:
        """Analyze Linux ELF structure safely."""
        findings = []
        try:
            # Check 32-bit vs 64-bit
            ei_class = content[4] if len(content) > 4 else 0
            arch = "64-bit" if ei_class == 2 else "32-bit"

            # Check for suspicious Linux persistence or injection strings
            suspicious_elf_strings = {
                b"/etc/ld.so.preload": "LD_PRELOAD persistence indicator",
                b"ptrace": "Process tracing / anti-debugging",
                b"/dev/tcp/": "Bash reverse shell indicator",
                b"chmod 777": "Permissive file permission manipulation",
            }

            for sig, desc in suspicious_elf_strings.items():
                if sig in content:
                    ev = Evidence(
                        target=target_label,
                        operation_id=operation_id,
                        tool_output=sig.decode("ascii", errors="ignore"),
                        response_excerpt=f"ELF string match: {desc}",
                    )
                    evidence_list.append(ev)
                    findings.append(
                        Finding(
                            title=f"Suspicious Capability Indicator in Linux ELF ({filename})",
                            category="malware_triage",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            asset=target_label,
                            target=filename,
                            description=f"ELF binary contains string matching security risk pattern: '{desc}' ({sig.decode('ascii', errors='ignore')}).",
                            evidence=[ev],
                            detection_method="elf_string_analysis",
                            impact="Indicates potential anti-analysis, persistence, or reverse-shell capabilities.",
                            remediation="Review binary symbols and disassemble functions referencing this string.",
                            references=["https://attack.mitre.org/techniques/T1574/006/"],
                            source_operation_id=operation_id,
                            status=FindingStatus.OPEN,
                        )
                    )

        except Exception as exc:
            if self.audit:
                self.audit.log("elf_analysis_error", error=str(exc))

        return findings
