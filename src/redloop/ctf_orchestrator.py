"""CTF Orchestrator: Multi-strategy, multi-provider, bounded CTF solver.

Requirements implemented:
1. Broader file handling (nested archives, .pka/.pkt packet tracer, unknown binary triage).
2. Live progress narration (event emitter pattern with present-tense descriptions).
3. Multi-strategy escalation (Tier 1 deterministic -> Tier 2 narrow LLM -> Tier 3 lateral moves).
4. Provider fallback on failure via SmartRouter.
5. Concurrency across files for Tier 1 decodes.
6. Hard bounds (wall-clock budget per file, total LLM calls per file).
"""

from __future__ import annotations

import concurrent.futures
import io
import re
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from redloop.ctf_files import FileCategory, FlagDetector, find_flags
from redloop.ctf_router import (
    BinaryTriageResult,
    NestedArchiveExtractor,
    PacketTracerExtractor,
    classify_file,
    triage_unknown_binary,
)
from redloop.ctf_strategies import Tier1Decoders
from redloop.llm import LLMClient, Provider, get_llm
from redloop.router import RoutingError, SmartRouter, TaskComplexity

DEFAULT_WALL_CLOCK_BUDGET = 600.0  # 10 minutes per file
DEFAULT_MAX_LLM_CALLS = 40  # 40 LLM calls per file
DEFAULT_TIER2_RETRIES = 4
DEFAULT_MAX_LATERAL_THEORIES = 3

_PYTHON_CODE_BLOCK = re.compile(r"```(?:python)?\s*([\s\S]*?)```", re.IGNORECASE)


@dataclass(slots=True)
class AttemptRecord:
    tier: int
    attempt_number: int
    theory_name: str
    script: str
    output: str
    success: bool
    flags: list[str] = field(default_factory=list)
    provider_used: str | None = None
    error: str | None = None


@dataclass(slots=True)
class FileSolveReport:
    filename: str
    category: FileCategory
    solved: bool
    flags: list[str] = field(default_factory=list)
    tier1_methods: list[str] = field(default_factory=list)
    attempts: list[AttemptRecord] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    llm_calls: int = 0
    budget_exhausted: bool = False
    notes: str = ""


@dataclass(slots=True)
class CTFSolveResult:
    archive_name: str
    solved: bool
    flags: list[str] = field(default_factory=list)
    file_reports: list[FileSolveReport] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    total_elapsed_seconds: float = 0.0


class CTFOrchestrator:
    """General-purpose CTF solver orchestrator with bounded escalation and live narration."""

    def __init__(
        self,
        smart_router: SmartRouter | None = None,
        wall_clock_budget: float = DEFAULT_WALL_CLOCK_BUDGET,
        max_llm_calls: int = DEFAULT_MAX_LLM_CALLS,
        max_tier2_retries: int = DEFAULT_TIER2_RETRIES,
        max_lateral_theories: int = DEFAULT_MAX_LATERAL_THEORIES,
        custom_flag_prefixes: list[str] | None = None,
        on_event: Callable[[str], None] | None = None,
    ):
        if smart_router is None:
            try:
                client = get_llm()
            except Exception:
                client = LLMClient()
            smart_router = SmartRouter(client)
        self.router = smart_router
        self.wall_clock_budget = wall_clock_budget
        self.max_llm_calls = max_llm_calls
        self.max_tier2_retries = max_tier2_retries
        self.max_lateral_theories = max_lateral_theories
        self.custom_flag_prefixes = custom_flag_prefixes or []
        self.on_event = on_event
        self._events: list[str] = []

    def emit(self, event_text: str) -> None:
        """Record and emit a live present-tense progress narration event."""
        self._events.append(event_text)
        if self.on_event:
            try:
                self.on_event(event_text)
            except Exception:
                pass

    def extract_archive(self, archive_name: str, data: bytes) -> dict[str, bytes]:
        """Extract files from a zip, tar, or supported archive format."""
        self.emit(f"Extracting {archive_name}")
        extracted: dict[str, bytes] = {}
        lower_name = archive_name.lower()

        # ZIP
        if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or lower_name.endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for info in zf.infolist():
                        if not info.is_dir():
                            extracted[info.filename] = zf.read(info)
                self.emit(f"Extracted {len(extracted)} files from {archive_name}")
                return extracted
            except Exception as exc:
                self.emit(f"Zip extraction error on {archive_name}: {exc}")

        # Tar / compressed tar
        if lower_name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")) or data.startswith(
            (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")
        ):
            try:
                extracted = NestedArchiveExtractor.extract_tar(data)
                self.emit(f"Extracted {len(extracted)} files via tar from {archive_name}")
                return extracted
            except Exception as exc:
                self.emit(f"Tar extraction error on {archive_name}: {exc}")

        # 7z
        if lower_name.endswith(".7z") or data.startswith(b"7z\xbc\xaf\x27\x1c"):
            try:
                extracted = NestedArchiveExtractor.extract_7z(data)
                self.emit(f"Extracted {len(extracted)} files via 7z from {archive_name}")
                return extracted
            except Exception as exc:
                self.emit(f"7z extraction error on {archive_name}: {exc}")

        # RAR
        if lower_name.endswith(".rar") or data.startswith(b"Rar!\x1a\x07"):
            try:
                extracted = NestedArchiveExtractor.extract_rar(data)
                self.emit(f"Extracted {len(extracted)} files via unrar from {archive_name}")
                return extracted
            except Exception as exc:
                self.emit(f"RAR extraction error on {archive_name}: {exc}")

        # If not an archive container, treat as a single file
        extracted[archive_name] = data
        return extracted

    def solve_archive(self, archive_name: str, archive_bytes: bytes) -> CTFSolveResult:
        """End-to-end solve workflow for a CTF challenge archive."""
        start_overall = time.time()
        extracted_files = self.extract_archive(archive_name, archive_bytes)
        file_reports: list[FileSolveReport] = []
        all_solved_flags: set[str] = set()

        if not extracted_files:
            self.emit(f"No files extracted from {archive_name}")
            return CTFSolveResult(
                archive_name=archive_name,
                solved=False,
                flags=[],
                file_reports=[],
                events=list(self._events),
                total_elapsed_seconds=time.time() - start_overall,
            )

        # ---------------------------------------------------------
        # REQUIREMENT 5: Speed - Concurrent Tier 1 decodes & classification
        # ---------------------------------------------------------
        self.emit(f"Running concurrent Tier 1 decodes across {len(extracted_files)} files")
        tier1_results: dict[str, tuple[FileCategory, list[str], list[str], Any]] = {}

        def _process_tier1(item: tuple[str, bytes]):
            fname, fdata = item
            cat = classify_file(fname, fdata)
            extra_meta = None
            pt_text = None

            # Handle Cisco Packet Tracer (.pka / .pkt)
            if PurePosixPath(fname.lower()).suffix in (".pka", ".pkt"):
                extracted_xml, status = PacketTracerExtractor.extract(fdata)
                if extracted_xml:
                    pt_text = extracted_xml
                    extra_meta = {"pt_status": status, "pt_xml_bytes": len(extracted_xml)}
                else:
                    extra_meta = {"pt_status": "opaque_binary_fallback"}

            # Triage unknown binary if applicable
            if cat in (FileCategory.BINARY, FileCategory.UNKNOWN):
                triage = triage_unknown_binary(fname, fdata)
                if extra_meta is None:
                    extra_meta = {}
                extra_meta["triage"] = triage

            # Run Tier 1 decoders on file data and any extracted Packet Tracer text
            flags_found, methods_used = Tier1Decoders.execute(
                fdata,
                custom_prefixes=self.custom_flag_prefixes,
                on_progress=lambda msg: self.emit(f"{fname}: {msg}"),
            )
            if pt_text:
                pt_flags = find_flags(pt_text, self.custom_flag_prefixes)
                if pt_flags:
                    flags_found = sorted(set(flags_found) | set(pt_flags))
                    methods_used.append("packet_tracer_xml")

            return fname, cat, flags_found, methods_used, extra_meta

        num_workers = min(8, max(1, len(extracted_files)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_process_tier1, (fn, fd)) for fn, fd in extracted_files.items()]
            for future in concurrent.futures.as_completed(futures):
                try:
                    fname, cat, flags, methods, extra_meta = future.result()
                    tier1_results[fname] = (cat, flags, methods, extra_meta)
                    if flags:
                        self.emit(f"Flag pattern matched in {fname} via Tier 1: {flags[0]}")
                        all_solved_flags.update(flags)
                except Exception as exc:
                    self.emit(f"Tier 1 task failed on file: {exc}")

        # ---------------------------------------------------------
        # Process files that did not yield flags in Tier 1
        # ---------------------------------------------------------
        for fname, fdata in extracted_files.items():
            if fname not in tier1_results:
                continue
            cat, t1_flags, t1_methods, extra_meta = tier1_results[fname]
            file_report = FileSolveReport(
                filename=fname,
                category=cat,
                solved=bool(t1_flags),
                flags=list(t1_flags),
                tier1_methods=t1_methods,
            )

            # If already solved in Tier 1, skip LLM escalation
            if t1_flags:
                file_reports.append(file_report)
                continue

            # Escalate unsolved file to Tier 2 and Tier 3
            self._escalate_file(fname, fdata, file_report, extra_meta)
            if file_report.flags:
                all_solved_flags.update(file_report.flags)
            file_reports.append(file_report)

        total_elapsed = time.time() - start_overall
        is_solved = len(all_solved_flags) > 0
        status_msg = f"Challenge solve complete: found {len(all_solved_flags)} flags in {total_elapsed:.1f}s"
        self.emit(status_msg)

        return CTFSolveResult(
            archive_name=archive_name,
            solved=is_solved,
            flags=sorted(all_solved_flags),
            file_reports=file_reports,
            events=list(self._events),
            total_elapsed_seconds=total_elapsed,
        )

    def _escalate_file(
        self,
        filename: str,
        data: bytes,
        report: FileSolveReport,
        extra_meta: dict[str, Any] | None,
    ) -> None:
        """Run Tier 2 narrow decode scripts and Tier 3 lateral theories within hard bounds."""
        file_start = time.time()
        self.emit(f"Tier 1 exhausted for '{filename}' — escalating to Tier 2 (LLM decode script)")

        # Prepare summary of file context
        triage: BinaryTriageResult | None = extra_meta.get("triage") if extra_meta else None
        if not triage:
            triage = triage_unknown_binary(filename, data)

        context_summary = triage.to_summary()
        if extra_meta and "pt_status" in extra_meta:
            context_summary += f"\nPacket Tracer Status: {extra_meta['pt_status']}"

        # ---------------------------------------------------------
        # TIER 2: LLM-generated narrow decode scripts with bounded retry
        # ---------------------------------------------------------
        tier2_prompt = (
            f"You are analyzing a CTF challenge file: '{filename}'.\n"
            f"Category: {report.category.value}\n\n"
            f"FILE TRIAGE DETAILS:\n{context_summary}\n\n"
            "Write a self-contained Python 3 script to decode or inspect this data to recover the flag.\n"
            "The data bytes of the file can be accessed from a local file named 'payload.bin'.\n"
            "Print any decoded strings or candidates to stdout. If you find a flag (like flag{...} or CTF{...}), print it.\n"
            "Return only the executable Python code inside a ```python ``` block."
        )

        attempts_history: list[AttemptRecord] = []
        tier2_success = False

        for attempt in range(1, self.max_tier2_retries + 1):
            if self._check_bounds(file_start, report):
                return

            self.emit(f"Attempt {attempt}/{self.max_tier2_retries} for '{filename}': generating decode script")
            report.llm_calls += 1

            script, provider = self._call_smart_router(
                system_prompt="You are an expert CTF reverse engineer and cryptanalyst.",
                user_prompt=tier2_prompt if attempt == 1 else self._build_retry_prompt(tier2_prompt, attempts_history),
                attempt_label=f"Attempt {attempt}/{self.max_tier2_retries}",
            )

            if not script:
                continue

            # Execute the generated script
            run_out, err, ok = self._execute_script(script, data)
            flags = find_flags(run_out, self.custom_flag_prefixes)

            rec = AttemptRecord(
                tier=2,
                attempt_number=attempt,
                theory_name="narrow_decode_script",
                script=script,
                output=run_out,
                success=bool(flags),
                flags=flags,
                provider_used=provider,
                error=err if not ok else None,
            )
            attempts_history.append(rec)
            report.attempts.append(rec)

            if flags:
                tier2_success = True
                report.solved = True
                report.flags.extend(flags)
                self.emit(f"Flag pattern matched: {flags[0]} (Tier 2, attempt {attempt})")
                break
            else:
                self.emit(f"Attempt {attempt}/{self.max_tier2_retries} for '{filename}' produced no flag")

        if tier2_success:
            report.elapsed_seconds = time.time() - file_start
            return

        # ---------------------------------------------------------
        # TIER 3: LLM-generated broad / lateral move step (cap at 3 distinct theories)
        # ---------------------------------------------------------
        self.emit(f"Tier 2 exhausted for '{filename}' — escalating to Tier 3 (lateral moves)")

        for theory_idx in range(1, self.max_lateral_theories + 1):
            if self._check_bounds(file_start, report):
                return

            self.emit(
                f"Attempt {theory_idx}/{self.max_lateral_theories} lateral theory for '{filename}': "
                "exploring alternative decoding theory"
            )
            report.llm_calls += 1

            tier3_prompt = (
                f"You are analyzing CTF artifact: '{filename}'.\n"
                f"Category: {report.category.value}\n\n"
                f"FILE TRIAGE DETAILS:\n{context_summary}\n\n"
                "PREVIOUS UNSUCCESSFUL ATTEMPTS AND THEORIES:\n"
                f"{self._format_attempts_context(attempts_history)}\n\n"
                f"LATERAL THEORY {theory_idx} REQUEST:\n"
                "The previous theories failed to recover the flag. Do NOT fix the same code or re-use the same theory.\n"
                "Propose a completely DIFFERENT angle or interpretation (e.g. steganography, frequency domain/audio modulation, "
                "custom cipher, protocol parsing, mathematical transform, or relativistic offset/dilation calculation).\n"
                "Write a self-contained Python script accessing 'payload.bin' that implements this new theory.\n"
                "Print candidates or recovered flags to stdout. Wrap your code inside a ```python ``` block."
            )

            script, provider = self._call_smart_router(
                system_prompt="You are an expert CTF solver seeking creative lateral decoding theories.",
                user_prompt=tier3_prompt,
                attempt_label=f"Lateral Theory {theory_idx}/{self.max_lateral_theories}",
            )

            if not script:
                continue

            run_out, err, ok = self._execute_script(script, data)
            flags = find_flags(run_out, self.custom_flag_prefixes)

            rec = AttemptRecord(
                tier=3,
                attempt_number=theory_idx,
                theory_name=f"lateral_theory_{theory_idx}",
                script=script,
                output=run_out,
                success=bool(flags),
                flags=flags,
                provider_used=provider,
                error=err if not ok else None,
            )
            attempts_history.append(rec)
            report.attempts.append(rec)

            if flags:
                report.solved = True
                report.flags.extend(flags)
                self.emit(f"Flag pattern matched: {flags[0]} (Tier 3, lateral theory {theory_idx})")
                break
            else:
                self.emit(f"Lateral theory {theory_idx}/{self.max_lateral_theories} for '{filename}' yielded no flag")

        report.elapsed_seconds = time.time() - file_start
        if not report.solved and not report.budget_exhausted:
            report.notes = "All three tiers exhausted; no flag matching patterns found."
            self.emit(f"File '{filename}' not solved after exhausting Tier 1, Tier 2, and Tier 3")

    def _check_bounds(self, file_start: float, report: FileSolveReport) -> bool:
        """Check wall-clock and call limits (Requirement 6)."""
        elapsed = time.time() - file_start
        if elapsed >= self.wall_clock_budget:
            report.budget_exhausted = True
            report.elapsed_seconds = elapsed
            report.notes = "Wall-clock budget exhausted"
            self.emit(f"Budget exhausted for '{report.filename}', not solved (time limit {self.wall_clock_budget}s hit)")
            return True

        if report.llm_calls >= self.max_llm_calls:
            report.budget_exhausted = True
            report.elapsed_seconds = elapsed
            report.notes = "LLM call budget exhausted"
            self.emit(f"Budget exhausted for '{report.filename}', not solved (call limit {self.max_llm_calls} hit)")
            return True

        return False

    def _call_smart_router(
        self,
        system_prompt: str,
        user_prompt: str,
        attempt_label: str,
    ) -> tuple[str | None, str | None]:
        """Invoke LLM via SmartRouter with automatic provider fallback (Requirement 4)."""
        try:
            res = self.router.route_and_complete(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                complexity=TaskComplexity.MODERATE,
                max_tokens=2_048,
                timeout=45,
                on_event=lambda ev: self.emit(f"{attempt_label}: {ev}"),
            )
            raw_text = res.get("text", "")
            provider = res.get("provider", "unknown")
            self.emit(f"Provider {provider} answered {attempt_label}")

            # Extract python code block
            match = _PYTHON_CODE_BLOCK.search(raw_text)
            if match:
                return match.group(1).strip(), provider
            return raw_text.strip(), provider
        except RoutingError as exc:
            self.emit(f"{attempt_label}: LLM routing failed: {exc}")
            return None, None
        except Exception as exc:
            self.emit(f"{attempt_label}: Error: {exc}")
            return None, None

    def _execute_script(self, script: str, payload_bytes: bytes) -> tuple[str, str, bool]:
        """Execute generated Python script safely in a temporary sandbox directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            script_file = tmp_path / "solution.py"
            payload_file = tmp_path / "payload.bin"

            script_file.write_text(script, encoding="utf-8")
            payload_file.write_bytes(payload_bytes)

            try:
                proc = subprocess.run(
                    [sys.executable, "-u", str(script_file)],
                    cwd=str(tmp_path),
                    capture_output=True,
                    text=True,
                    timeout=15,  # 15 second script execution limit
                )
                output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
                return output.strip(), proc.stderr.strip(), proc.returncode == 0
            except subprocess.TimeoutExpired:
                return "Script timed out after 15 seconds", "TimeoutExpired", False
            except Exception as exc:
                return f"Execution error: {exc}", str(exc), False

    def _build_retry_prompt(self, original_prompt: str, history: list[AttemptRecord]) -> str:
        """Construct feedback prompt with prior error details for narrow Tier 2 retries."""
        last = history[-1]
        err_msg = last.error or "Script executed but did not output a valid flag."
        return (
            f"{original_prompt}\n\n"
            f"PREVIOUS ATTEMPT FAILED:\n"
            f"Error/Output:\n{err_msg[:1000]}\n\n"
            "Please fix the code or refine the decode logic and return the corrected Python script inside ```python ```."
        )

    def _format_attempts_context(self, history: list[AttemptRecord]) -> str:
        """Summarize all previous failed attempts for lateral Tier 3 thinking."""
        lines = []
        for i, h in enumerate(history, 1):
            sample = h.output[:200].replace("\n", " ") if h.output else "no output"
            lines.append(f"- Attempt {i} ({h.theory_name}): {h.error or 'no flag found'}; output sample: '{sample}'")
        return "\n".join(lines)
