"""Broader file handling and classification for CTF artifacts.

Handles:
- Cisco Packet Tracer (.pka, .pkt): zlib-decompressed XML extraction with graceful fallback
- PCAP/PCAPNG network captures
- Audio/Signal challenges (.wav, .raw)
- Disk images (.img, .dd)
- Nested archives (.tar.gz, .7z, .rar) with clear errors when external tools are missing
- Generic unknown binary triage: file magic, strings -n 8, and entropy via StaticAnalyzer
"""

from __future__ import annotations

import io
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any

from redloop.ctf_files import FileCategory, _has_zip_signature, _PCAP_SIGNATURES
from redloop.forensics import StaticAnalyzer

# Strings run pattern for length >= 8
_STRINGS_N8 = re.compile(rb"[\x20-\x7e]{8,}")


@dataclass(slots=True)
class BinaryTriageResult:
    """Triage output for generic unknown binaries to enable LLM reasoning."""

    filename: str
    size_bytes: int
    magic_type: str
    entropy: float
    strings_sample: list[str]
    hex_preview: str

    def to_summary(self) -> str:
        lines = [
            f"File: {self.filename} ({self.magic_type}, {self.size_bytes:,} bytes, entropy={self.entropy:.2f})",
            "Strings (-n 8 sample):",
        ]
        if self.strings_sample:
            lines.extend(f"  {s}" for s in self.strings_sample[:30])
        else:
            lines.append("  (no printable runs of length >= 8)")
        lines.append("Hex Preview (first 256 bytes):")
        lines.append(self.hex_preview)
        return "\n".join(lines)


class PacketTracerExtractor:
    """Extracts internal XML configurations from Cisco Packet Tracer (.pka, .pkt) files."""

    @staticmethod
    def extract(data: bytes) -> tuple[str | None, str]:
        """Attempt to extract zlib-compressed XML payload from .pka / .pkt.

        Note: Newer Cisco Packet Tracer versions use proprietary/custom encryption
        controlled by Packet Tracer itself. If extraction fails, we fall back to
        treating it as an opaque binary for strings/entropy analysis rather than crashing.
        """
        # Scan for common zlib stream headers: \x78\x9c, \x78\xda, \x78\x01, \x78\x5e
        candidates: list[bytes] = []
        for header in (b"\x78\x9c", b"\x78\xda", b"\x78\x01", b"\x78\x5e"):
            start = 0
            while True:
                idx = data.find(header, start)
                if idx < 0 or len(candidates) >= 5:
                    break
                try:
                    decompressed = zlib.decompress(data[idx:])
                    if b"<" in decompressed and (b"</" in decompressed or b"/>" in decompressed):
                        return decompressed.decode("utf-8", errors="replace"), "zlib_xml"
                    candidates.append(decompressed)
                except Exception:
                    pass
                start = idx + 1

        if candidates:
            # Return the largest decompressed stream decoded
            largest = max(candidates, key=len)
            return largest.decode("utf-8", errors="replace"), "zlib_payload"

        return None, "encrypted_or_opaque_pt"


class NestedArchiveExtractor:
    """Extracts nested archives with explicit tool-availability errors."""

    @staticmethod
    def extract_tar(data: bytes) -> dict[str, bytes]:
        """Extract tar / tar.gz / tar.bz2 / tar.xz archives in memory."""
        extracted: dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            for member in tar.getmembers():
                if member.isfile():
                    f = tar.extractfile(member)
                    if f:
                        extracted[member.name] = f.read()
        return extracted

    @staticmethod
    def extract_7z(data: bytes) -> dict[str, bytes]:
        """Extract .7z archives using 7z CLI or raise clear error."""
        seven_zip = shutil.which("7z") or shutil.which("7za")
        if not seven_zip:
            raise RuntimeError(
                "Extraction of .7z archives requires the '7z' command-line utility installed in PATH."
            )
        extracted: dict[str, bytes] = {}
        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "input.7z"
            archive_path.write_bytes(data)
            out_dir = Path(tmp_dir) / "out"
            out_dir.mkdir()
            res = subprocess.run(
                [seven_zip, "x", str(archive_path), f"-o{out_dir}", "-y"],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"7z extraction failed: {res.stderr}")
            for item in out_dir.rglob("*"):
                if item.is_file():
                    extracted[str(item.relative_to(out_dir))] = item.read_bytes()
        return extracted

    @staticmethod
    def extract_rar(data: bytes) -> dict[str, bytes]:
        """Extract .rar archives using unrar CLI or raise clear error."""
        unrar = shutil.which("unrar") or shutil.which("rar")
        if not unrar:
            raise RuntimeError(
                "Extraction of .rar archives requires the 'unrar' command-line utility installed in PATH."
            )
        extracted: dict[str, bytes] = {}
        with tempfile.TemporaryDirectory() as tmp_dir:
            archive_path = Path(tmp_dir) / "input.rar"
            archive_path.write_bytes(data)
            out_dir = Path(tmp_dir) / "out"
            out_dir.mkdir()
            res = subprocess.run(
                [unrar, "x", "-y", str(archive_path), str(out_dir)],
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"unrar extraction failed: {res.stderr}")
            for item in out_dir.rglob("*"):
                if item.is_file():
                    extracted[str(item.relative_to(out_dir))] = item.read_bytes()
        return extracted


def triage_unknown_binary(filename: str, data: bytes) -> BinaryTriageResult:
    """Triage unknown binaries by extracting file magic, strings -n 8, and Shannon entropy."""
    size = len(data)
    entropy = StaticAnalyzer._entropy(data)
    magic_type = StaticAnalyzer._file_type(data)

    # Strings -n 8
    preview_bytes = data[: min(size, 262_144)]  # Up to 256KB
    strings_sample = [
        match.decode("ascii", errors="ignore")
        for match in _STRINGS_N8.findall(preview_bytes)
    ][:50]

    # Hex preview (first 256 bytes)
    chunk = data[: min(size, 256)]
    hex_lines = []
    for offset in range(0, len(chunk), 16):
        slice_bytes = chunk[offset : offset + 16]
        hex_str = " ".join(f"{b:02x}" for b in slice_bytes)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in slice_bytes)
        hex_lines.append(f"{offset:04x}: {hex_str:<48}  {ascii_str}")
    hex_preview = "\n".join(hex_lines)

    return BinaryTriageResult(
        filename=filename,
        size_bytes=size,
        magic_type=magic_type,
        entropy=entropy,
        strings_sample=strings_sample,
        hex_preview=hex_preview,
    )


def classify_file(filename: str, data: bytes) -> FileCategory:
    """Recognize and route uncommon formats by extension and signature."""
    lower_name = filename.lower()
    ext = PurePosixPath(lower_name).suffix
    double_ext = (
        "".join(PurePosixPath(lower_name).suffixes[-2:])
        if len(PurePosixPath(lower_name).suffixes) >= 2
        else ext
    )

    # 1. Archives
    if _has_zip_signature(data) or ext == ".zip":
        return FileCategory.ARCHIVE
    if double_ext in (".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tar") or data.startswith(
        (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
    ):
        return FileCategory.ARCHIVE
    if ext in (".7z", ".rar") or data.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07")):
        return FileCategory.ARCHIVE

    # 2. Cisco Packet Tracer (.pka, .pkt)
    if ext in (".pka", ".pkt"):
        return FileCategory.BINARY  # Handled as PT binary structure

    # 3. PCAP / PCAPNG
    if data.startswith(_PCAP_SIGNATURES) or ext in (".pcap", ".pcapng", ".cap"):
        return FileCategory.PCAP

    # 4. Images
    if data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        return FileCategory.IMAGE

    # 5. Text
    if data and b"\x00" not in data and sum(
        byte >= 0x20 or byte in (0x09, 0x0A, 0x0D) for byte in data
    ) / len(data) >= 0.85:
        return FileCategory.TEXT

    # 6. Default to binary
    return FileCategory.BINARY if data else FileCategory.UNKNOWN
