"""CTF solving extensions and orchestrator."""

from modules.ctf.file_router import (
    BinaryTriageResult,
    FileCategory,
    NestedArchiveExtractor,
    PacketTracerExtractor,
    classify_file,
    triage_unknown_binary,
)
from modules.ctf.flag_detector import FlagDetector, find_flags
from modules.ctf.strategies import Tier1Decoders
from modules.ctf.ctf_orchestrator import (
    AttemptRecord,
    CTFOrchestrator,
    CTFSolveResult,
    FileSolveReport,
)

__all__ = [
    "BinaryTriageResult",
    "FileCategory",
    "NestedArchiveExtractor",
    "PacketTracerExtractor",
    "classify_file",
    "triage_unknown_binary",
    "FlagDetector",
    "find_flags",
    "Tier1Decoders",
    "AttemptRecord",
    "CTFOrchestrator",
    "CTFSolveResult",
    "FileSolveReport",
]
