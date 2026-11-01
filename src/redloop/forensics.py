"""Bounded, static-only file triage. Uploaded content is never executed."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from pathlib import PureWindowsPath

from pydantic import BaseModel, ConfigDict, Field

from redloop.audit import AuditLogger
from redloop.memory import EpisodicMemory, MemoryRecord

MAX_FILE_SIZE = 16 * 1024 * 1024
MAX_RULE_FILES = 100
MAX_RULE_FILE_SIZE = 256 * 1024
MAX_RULE_BYTES = 2 * 1024 * 1024
MAX_IOCS_PER_KIND = 500
PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")
IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOMAIN_PATTERN = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![\w.-])"
)
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]{1,2048}", re.IGNORECASE)
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)


class FileProfile(BaseModel):
    filename: str
    sha256: str
    md5: str
    file_type: str
    size_bytes: int
    entropy: float
    warnings: list[str] = Field(default_factory=list)


class ExtractedIOCs(BaseModel):
    ips: list[str]
    domains: list[str]
    urls: list[str]
    emails: list[str]


class YaraMatch(BaseModel):
    rule_name: str
    tags: list[str]
    meta: dict[str, Any]


class ForensicsReport(BaseModel):
    profile: FileProfile
    yara_status: str
    yara_matches: list[YaraMatch]
    iocs: ExtractedIOCs


class YaraScanner:
    """Scan bytes using explicitly supplied, local YARA rules."""

    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)
        rule_paths = sorted(
            path for path in self.rules_dir.iterdir()
            if path.is_file() and path.suffix.lower() in {".yar", ".yara"}
        ) if self.rules_dir.is_dir() else []
        if not rule_paths:
            raise FileNotFoundError(
                f"No .yar or .yara rule files found in {self.rules_dir}"
            )
        if len(rule_paths) > MAX_RULE_FILES:
            raise ValueError(f"At most {MAX_RULE_FILES} YARA rule files are allowed")

        total_size = 0
        for path in rule_paths:
            size = path.stat().st_size
            if size > MAX_RULE_FILE_SIZE:
                raise ValueError(f"YARA rule file exceeds size limit: {path.name}")
            total_size += size
        if total_size > MAX_RULE_BYTES:
            raise ValueError("Combined YARA rule files exceed size limit")

        try:
            import yara
        except ImportError as exc:
            raise RuntimeError(
                "YARA scanning requires the optional dependency: "
                "pip install redloop[forensics]"
            ) from exc

        filepaths = {f"rule_{index}": str(path) for index, path in enumerate(rule_paths)}
        self.rules = yara.compile(filepaths=filepaths)

    def scan(self, file_bytes: bytes) -> list[YaraMatch]:
        matches = self.rules.match(data=file_bytes, timeout=5)
        return [
            YaraMatch(
                rule_name=match.rule,
                tags=list(match.tags),
                meta=dict(match.meta),
            )
            for match in matches
        ]


class ForensicsAnalyzer:
    """Analyze bounded file bytes without storing or executing the sample."""

    def __init__(
        self,
        audit: AuditLogger,
        yara_scanner: YaraScanner | None = None,
        memory: EpisodicMemory | None = None,
        max_file_size: int = MAX_FILE_SIZE,
    ):
        if isinstance(max_file_size, bool) or not 1 <= max_file_size <= MAX_FILE_SIZE:
            raise ValueError(f"max_file_size must be between 1 and {MAX_FILE_SIZE}")
        self.audit = audit
        self.yara_scanner = yara_scanner
        self.memory = memory
        self.max_file_size = max_file_size

    def analyze(self, file_bytes: bytes, original_filename: str) -> ForensicsReport:
        if not isinstance(file_bytes, bytes):
            raise TypeError("file_bytes must be bytes")
        filename = self._safe_filename(original_filename)
        if len(file_bytes) > self.max_file_size:
            self.audit.log(
                filename,
                "static_analysis",
                "forensics",
                "blocked",
                {"reason": "file_size_limit", "size_bytes": len(file_bytes)},
            )
            raise ValueError(f"File exceeds {self.max_file_size} byte limit")

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        md5 = hashlib.md5(file_bytes, usedforsecurity=False).hexdigest()
        file_type = self._file_type(file_bytes)
        entropy = self._entropy(file_bytes)
        warnings = []
        if file_type in {"application/x-dosexec", "application/x-elf"} and entropy >= 7.2:
            warnings.append(
                "Executable signature with high entropy; this may indicate packing "
                "or encryption and is not proof of malware."
            )
        profile = FileProfile(
            filename=filename,
            sha256=sha256,
            md5=md5,
            file_type=file_type,
            size_bytes=len(file_bytes),
            entropy=entropy,
            warnings=warnings,
        )
        iocs = self._extract_iocs(file_bytes)
        yara_matches = (
            self.yara_scanner.scan(file_bytes) if self.yara_scanner else []
        )
        yara_status = "scanned" if self.yara_scanner else "not_configured"

        self.audit.log(
            sha256,
            "static_analysis",
            "forensics",
            "success",
            {
                "filename": filename,
                "size_bytes": len(file_bytes),
                "file_type": file_type,
                "yara_status": yara_status,
                "yara_match_count": len(yara_matches),
                "ioc_counts": {
                    "ips": len(iocs.ips),
                    "domains": len(iocs.domains),
                    "urls": len(iocs.urls),
                    "emails": len(iocs.emails),
                },
            },
        )
        if self.memory:
            self.memory.store(
                MemoryRecord(
                    task_description="static file triage",
                    approach="hash, signature, entropy, printable IOC extraction, optional YARA",
                    outcome="success",
                    module="forensics",
                    details=(
                        f"type={file_type}; yara_matches={len(yara_matches)}; "
                        f"ioc_total={sum(len(values) for values in iocs.model_dump().values())}"
                    ),
                )
            )
        return ForensicsReport(
            profile=profile,
            yara_status=yara_status,
            yara_matches=yara_matches,
            iocs=iocs,
        )

    @staticmethod
    def _safe_filename(filename: str) -> str:
        if not isinstance(filename, str) or not filename.strip():
            return "unnamed"
        name = PureWindowsPath(filename).name
        name = Path(name).name
        safe = "".join(
            character for character in name[:255]
            if character.isprintable() and character not in "/\\"
        ).strip()
        return safe or "unnamed"

    @staticmethod
    def _file_type(data: bytes) -> str:
        if data.startswith(b"MZ"):
            return "application/x-dosexec"
        if data.startswith(b"\x7fELF"):
            return "application/x-elf"
        if data.startswith(b"%PDF-"):
            return "application/pdf"
        if data.startswith(b"PK\x03\x04"):
            return "application/zip"
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image/png"
        if data.startswith(b"\xff\xd8\xff"):
            return "image/jpeg"
        if data.startswith((b"GIF87a", b"GIF89a")):
            return "image/gif"
        if data.startswith(b"\x1f\x8b"):
            return "application/gzip"
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return "application/x-ole-storage"
        if data and b"\x00" not in data and sum(
            byte >= 0x20 or byte in (0x09, 0x0A, 0x0D) for byte in data
        ) / len(data) >= 0.85:
            return "text/plain"
        return "application/octet-stream"

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = -sum(
            (count / len(data)) * math.log2(count / len(data))
            for count in counts
            if count
        )
        return round(entropy, 2)

    @staticmethod
    def _extract_iocs(data: bytes) -> ExtractedIOCs:
        text = "\n".join(
            match.decode("ascii", errors="ignore")
            for match in PRINTABLE_RUN.findall(data)
        )
        ips = set()
        for candidate in IP_PATTERN.findall(text):
            try:
                ips.add(str(ipaddress.IPv4Address(candidate)))
            except ipaddress.AddressValueError:
                continue

        urls = {value.rstrip(".,);]") for value in URL_PATTERN.findall(text)}
        domains = set(DOMAIN_PATTERN.findall(text))
        for url in urls:
            try:
                hostname = urlsplit(url).hostname
            except ValueError:
                hostname = None
            if hostname:
                domains.add(hostname)

        emails = set(EMAIL_PATTERN.findall(text))
        return ExtractedIOCs(
            ips=sorted(ips)[:MAX_IOCS_PER_KIND],
            domains=sorted(domains, key=str.casefold)[:MAX_IOCS_PER_KIND],
            urls=sorted(urls)[:MAX_IOCS_PER_KIND],
            emails=sorted(emails, key=str.casefold)[:MAX_IOCS_PER_KIND],
        )


StaticAnalyzer = ForensicsAnalyzer
