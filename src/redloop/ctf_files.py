"""Bounded, in-memory CTF archive triage without executing sample content."""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import io
import re
import struct
import zipfile
import zlib
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from redloop.audit import AuditLogger
from redloop.memory import EpisodicMemory, MemoryRecord

MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_FILES = 100
MAX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
MAX_NESTED_ARCHIVE_DEPTH = 3
MAX_DECODE_DEPTH = 2
MAX_DECODE_VARIANTS = 12
MAX_DECODE_CANDIDATES = 8
MAX_DECODED_BYTES = 256 * 1024
MAX_DECODE_TOKEN_CHARS = 64 * 1024
MAX_FLAGS_PER_FILE = 20
MAX_FLAGS_TOTAL = 100
MAX_WARNINGS = 50

_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_PCAP_SIGNATURES = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
)
_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_BASE64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_HEX_TOKEN = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
_STANDARD_FLAG = re.compile(
    r"(?<![\w-])(?:flag|ctf)\{[^{}\r\n]{1,256}\}", re.IGNORECASE
)
_GENERIC_FLAG = re.compile(
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_]{1,48}\{[A-Za-z0-9_!@#$%^&*\-]{1,128}\}"
)
_PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class FileCategory(str, Enum):
    TEXT = "text"
    IMAGE = "image"
    ARCHIVE = "archive"
    BINARY = "binary"
    PCAP = "pcap"
    UNKNOWN = "unknown"


class CTFFileFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    category: FileCategory
    flags: list[str] = Field(default_factory=list)
    decode_methods: list[str] = Field(default_factory=list)
    skipped_reason: str | None = None


class CTFArchiveReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    archive_name: str
    archive_sha256: str
    status: Literal["solved", "not_found"]
    examined_files: int
    files: list[CTFFileFinding] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class _ArchiveBudget:
    def __init__(self) -> None:
        self.files_seen = 0
        self.uncompressed_bytes_read = 0
        self.findings: list[CTFFileFinding] = []
        self.flags: set[str] = set()
        self.warnings: list[str] = []

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(message)


class FlagDetector:
    """Find common flag wrappers and explicitly supplied safe prefixes."""

    def __init__(self, custom_prefixes: list[str] | None = None) -> None:
        prefixes = custom_prefixes or []
        if len(prefixes) > 10:
            raise ValueError("At most 10 custom flag prefixes are allowed")
        self.prefix_patterns: list[re.Pattern[str]] = []
        self.canonical_prefixes = {"flag", "ctf", "picoctf"}
        for prefix in prefixes:
            if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
                raise ValueError(
                    "Flag prefixes must be 1-64 letters, digits, underscores, "
                    "periods, or hyphens"
                )
            self.prefix_patterns.append(
                re.compile(re.escape(prefix) + r"\{[^{}\r\n]{1,256}\}")
            )
            self.canonical_prefixes.add(prefix.casefold())

    def find(self, text: str) -> list[str]:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        matches: set[str] = set()
        for pattern in (_STANDARD_FLAG, _GENERIC_FLAG, *self.prefix_patterns):
            for match in pattern.finditer(text):
                matches.add(match.group(0))
                if len(matches) >= MAX_FLAGS_PER_FILE:
                    return sorted(matches)
        return sorted(matches)

    def is_rot13_encoded_flag(self, value: str) -> bool:
        prefix = value.partition("{")[0].casefold()
        if prefix in self.canonical_prefixes:
            return False
        decoded = codecs.encode(value, "rot_13")
        return any(
            match.partition("{")[0].casefold() in self.canonical_prefixes
            for match in self.find(decoded)
        )


def find_flags(
    text: str, custom_prefixes: list[str] | None = None
) -> list[str]:
    """Return sorted unique flag-like strings without accepting arbitrary regexes."""
    return FlagDetector(custom_prefixes).find(text)


class CTFArchiveAnalyzer:
    """Inspect ZIP content in memory with bounded recursion and decoding."""

    def __init__(
        self,
        audit: AuditLogger | None = None,
        memory: EpisodicMemory | None = None,
    ) -> None:
        self.audit = audit
        self.memory = memory

    def analyze(
        self,
        archive_bytes: bytes,
        original_filename: str = "challenge.zip",
        flag_prefixes: list[str] | None = None,
    ) -> CTFArchiveReport:
        if not isinstance(archive_bytes, bytes):
            raise TypeError("archive_bytes must be bytes")
        if len(archive_bytes) > MAX_ARCHIVE_BYTES:
            self._log_oversize(len(archive_bytes))
            raise ValueError(f"Archive exceeds {MAX_ARCHIVE_BYTES} byte limit")

        archive_hash = hashlib.sha256(archive_bytes).hexdigest()
        target = f"archive-sha256:{archive_hash}"
        detector = FlagDetector(flag_prefixes)
        try:
            self._preflight_zip(archive_bytes)
        except ValueError:
            self._log(target, "failed", {"reason": "invalid_or_unsupported_zip"})
            raise

        budget = _ArchiveBudget()
        self._inspect_zip(
            archive_bytes,
            parent="",
            depth=0,
            detector=detector,
            budget=budget,
        )
        if not budget.findings:
            budget.warn("The archive contained no inspectable files.")

        report = CTFArchiveReport(
            archive_name=_safe_archive_name(original_filename),
            archive_sha256=archive_hash,
            status="solved" if budget.flags else "not_found",
            examined_files=len(budget.findings),
            files=budget.findings,
            flags=sorted(budget.flags)[:MAX_FLAGS_TOTAL],
            warnings=budget.warnings,
        )
        self._log(
            target,
            "success",
            {
                "status": report.status,
                "files_examined": report.examined_files,
                "flags_found": len(report.flags),
                "warning_count": len(report.warnings),
            },
        )
        if self.memory:
            self.memory.store(
                MemoryRecord(
                    task_description="local CTF archive flag analysis",
                    approach=(
                        "bounded ZIP inspection and base64 hex rot13 decoding"
                    ),
                    outcome="success" if report.flags else "failure",
                    module="ctf_file_analyzer",
                    details=(
                        f"files={report.examined_files}; "
                        f"flags={len(report.flags)}; status={report.status}"
                    ),
                )
            )
        return report

    def _inspect_zip(
        self,
        archive_bytes: bytes,
        parent: str,
        depth: int,
        detector: FlagDetector,
        budget: _ArchiveBudget,
    ) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    if budget.files_seen >= MAX_ARCHIVE_FILES:
                        budget.warn(
                            f"File-count limit reached at {MAX_ARCHIVE_FILES} entries."
                        )
                        return
                    budget.files_seen += 1
                    member_path = _safe_member_path(parent, info.filename)
                    category = _classify_file(info.filename, b"")

                    if info.file_size > MAX_ENTRY_BYTES:
                        budget.findings.append(
                            CTFFileFinding(
                                path=member_path,
                                category=category,
                                skipped_reason="entry_size_limit",
                            )
                        )
                        budget.warn(f"Skipped {member_path}: entry size limit.")
                        continue
                    if (
                        budget.uncompressed_bytes_read + info.file_size
                        > MAX_TOTAL_UNCOMPRESSED_BYTES
                    ):
                        budget.findings.append(
                            CTFFileFinding(
                                path=member_path,
                                category=category,
                                skipped_reason="total_uncompressed_size_limit",
                            )
                        )
                        budget.warn(
                            f"Skipped {member_path}: total uncompressed size limit."
                        )
                        continue

                    try:
                        with archive.open(info) as member:
                            content = member.read(MAX_ENTRY_BYTES + 1)
                    except (
                        OSError,
                        RuntimeError,
                        EOFError,
                        zipfile.BadZipFile,
                        zlib.error,
                    ) as exc:
                        budget.findings.append(
                            CTFFileFinding(
                                path=member_path,
                                category=category,
                                skipped_reason="entry_read_error",
                            )
                        )
                        budget.warn(
                            f"Skipped {member_path}: {type(exc).__name__}."
                        )
                        continue

                    if len(content) > MAX_ENTRY_BYTES:
                        budget.findings.append(
                            CTFFileFinding(
                                path=member_path,
                                category=category,
                                skipped_reason="entry_size_limit",
                            )
                        )
                        budget.warn(f"Skipped {member_path}: entry size limit.")
                        continue
                    if (
                        budget.uncompressed_bytes_read + len(content)
                        > MAX_TOTAL_UNCOMPRESSED_BYTES
                    ):
                        budget.findings.append(
                            CTFFileFinding(
                                path=member_path,
                                category=category,
                                skipped_reason="total_uncompressed_size_limit",
                            )
                        )
                        budget.warn(
                            f"Skipped {member_path}: total uncompressed size limit."
                        )
                        continue

                    budget.uncompressed_bytes_read += len(content)
                    category = _classify_file(info.filename, content)
                    flags, methods = _scan_content(content, detector)
                    budget.findings.append(
                        CTFFileFinding(
                            path=member_path,
                            category=category,
                            flags=flags,
                            decode_methods=methods,
                        )
                    )
                    budget.flags.update(flags)

                    if category != FileCategory.ARCHIVE:
                        continue
                    if depth >= MAX_NESTED_ARCHIVE_DEPTH:
                        budget.warn(
                            f"Nested archive depth limit reached at {member_path}."
                        )
                        continue
                    if not _has_zip_signature(content):
                        continue
                    try:
                        self._preflight_zip(content)
                    except ValueError:
                        budget.warn(
                            f"Skipped nested archive {member_path}: "
                            "invalid or unsupported ZIP."
                        )
                        continue
                    self._inspect_zip(
                        content,
                        parent=member_path,
                        depth=depth + 1,
                        detector=detector,
                        budget=budget,
                    )
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, EOFError):
            budget.warn("Could not inspect a ZIP archive; it may be damaged.")

    @staticmethod
    def _preflight_zip(archive_bytes: bytes) -> int:
        if not _has_zip_signature(archive_bytes):
            raise ValueError("Input is not a valid ZIP archive")
        tail_length = min(len(archive_bytes), 22 + 65_535)
        tail = archive_bytes[-tail_length:]
        end_offset = tail.rfind(b"PK\x05\x06")
        if end_offset < 0 or end_offset + 22 > len(tail):
            raise ValueError("Input is not a valid ZIP archive")
        comment_length = struct.unpack_from("<H", tail, end_offset + 20)[0]
        if end_offset + 22 + comment_length > len(tail):
            raise ValueError("Input is not a valid ZIP archive")
        disk_number, central_directory_disk, disk_entries, total_entries = (
            struct.unpack_from("<HHHH", tail, end_offset + 4)
        )
        if disk_number or central_directory_disk or disk_entries != total_entries:
            raise ValueError("Multi-disk ZIP archives are not supported")
        if total_entries == 0xFFFF:
            raise ValueError("ZIP64 archives are not supported")
        if total_entries > MAX_ARCHIVE_FILES:
            raise ValueError(
                f"Archive exceeds {MAX_ARCHIVE_FILES} file entry limit"
            )
        return total_entries

    def _log(self, target: str, status: str, details: dict[str, object]) -> None:
        if self.audit:
            self.audit.log(
                target,
                "ctf_archive_analysis",
                "ctf_file_analyzer",
                status,
                details,
            )

    def _log_oversize(self, size_bytes: int) -> None:
        if self.audit:
            self.audit.log(
                "oversized-local-archive",
                "ctf_archive_analysis",
                "ctf_file_analyzer",
                "blocked",
                {"reason": "archive_size_limit", "size_bytes": size_bytes},
            )


def _safe_archive_name(filename: str) -> str:
    if not isinstance(filename, str) or not filename.strip():
        return "challenge.zip"
    name = PureWindowsPath(filename.replace("/", "\\")).name
    name = "".join(
        character for character in name[:255] if character.isprintable()
    ).strip()
    return name or "challenge.zip"


def _safe_member_path(parent: str, filename: str) -> str:
    parts = PurePosixPath(filename.replace("\\", "/")).parts
    safe_parts = [
        "".join(character for character in part if character.isprintable())
        for part in parts
        if part not in {"", "/", ".", ".."}
    ]
    name = "/".join(part for part in safe_parts if part) or "unnamed"
    return f"{parent}/{name}" if parent else name


def _has_zip_signature(data: bytes) -> bool:
    return data.startswith(_ZIP_SIGNATURES)


def _classify_file(filename: str, data: bytes) -> FileCategory:
    if _has_zip_signature(data) or filename.lower().endswith(".zip"):
        return FileCategory.ARCHIVE
    if data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        return FileCategory.IMAGE
    if data.startswith(_PCAP_SIGNATURES):
        return FileCategory.PCAP
    if data and b"\x00" not in data and sum(
        byte >= 0x20 or byte in (0x09, 0x0A, 0x0D) for byte in data
    ) / len(data) >= 0.85:
        return FileCategory.TEXT
    return FileCategory.BINARY if data else FileCategory.UNKNOWN


def _searchable_text(data: bytes) -> str:
    decoded = data.decode("utf-8", errors="ignore")
    printable = "\n".join(
        match.decode("ascii", errors="ignore")
        for match in _PRINTABLE_RUN.findall(data)
    )
    return f"{decoded}\n{printable}"


def _scan_content(
    data: bytes, detector: FlagDetector
) -> tuple[list[str], list[str]]:
    pending: list[tuple[str, bytes, int]] = [("raw", data, 0)]
    seen: set[bytes] = set()
    flags: set[str] = set()
    methods: list[str] = []

    while pending and len(methods) < MAX_DECODE_VARIANTS:
        method, payload, depth = pending.pop(0)
        digest = hashlib.sha256(payload).digest()
        if digest in seen:
            continue
        seen.add(digest)
        if method not in methods:
            methods.append(method)
        text = _searchable_text(payload)
        flags.update(
            flag
            for flag in detector.find(text)
            if not detector.is_rot13_encoded_flag(flag)
        )
        if len(flags) >= MAX_FLAGS_PER_FILE:
            return sorted(flags)[:MAX_FLAGS_PER_FILE], methods
        if depth >= MAX_DECODE_DEPTH or not text:
            continue

        candidates: list[tuple[str, bytes]] = []
        for match in _BASE64_TOKEN.finditer(text):
            token = match.group(0)
            if len(token) > MAX_DECODE_TOKEN_CHARS:
                continue
            padded = token + "=" * (-len(token) % 4)
            try:
                decoded = base64.b64decode(
                    padded.encode("ascii"), altchars=b"-_", validate=True
                )
            except (binascii.Error, ValueError):
                continue
            if decoded and len(decoded) <= MAX_DECODED_BYTES:
                candidates.append(("base64", decoded))
            if len(candidates) >= MAX_DECODE_CANDIDATES:
                break

        if len(candidates) < MAX_DECODE_CANDIDATES:
            for match in _HEX_TOKEN.finditer(text):
                token = match.group(0)
                if len(token) > MAX_DECODE_TOKEN_CHARS:
                    continue
                try:
                    decoded = bytes.fromhex(token)
                except ValueError:
                    continue
                if decoded and len(decoded) <= MAX_DECODED_BYTES:
                    candidates.append(("hex", decoded))
                if len(candidates) >= MAX_DECODE_CANDIDATES:
                    break

        if len(candidates) < MAX_DECODE_CANDIDATES:
            rot13 = codecs.encode(text, "rot_13").encode("utf-8")
            if rot13 != payload and len(rot13) <= MAX_DECODED_BYTES:
                candidates.append(("rot13", rot13))

        for candidate in candidates:
            if len(pending) + len(methods) >= MAX_DECODE_VARIANTS:
                break
            pending.append((candidate[0], candidate[1], depth + 1))

    return sorted(flags)[:MAX_FLAGS_PER_FILE], methods
