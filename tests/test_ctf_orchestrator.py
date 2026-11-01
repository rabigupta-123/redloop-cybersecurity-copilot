import base64
import io
import time
import zipfile
from types import SimpleNamespace

import pytest

from modules.ctf import (
    CTFOrchestrator,
    FileCategory,
    Tier1Decoders,
    find_flags,
)
from redloop.llm import LLMError, Provider
from redloop.router import SmartRouter, TaskComplexity


class FakeLLMClient:
    def __init__(self, responses=None, fails_on=None):
        self.responses = list(responses or [])
        self.response_idx = 0
        self.fails_on = fails_on or []
        self.calls = []
        self.settings = SimpleNamespace(allow_cloud_routing=True)

    def is_provider_configured(self, provider):
        return True

    def complete(self, system_prompt, user_prompt, provider=None, **kwargs):
        self.calls.append({"provider": provider, "user_prompt": user_prompt})
        if provider in self.fails_on:
            raise LLMError(f"Simulated provider failure on {provider.value}")
        if self.response_idx < len(self.responses):
            text = self.responses[self.response_idx]
            self.response_idx += 1
        else:
            text = "```python\nprint('no flag')\n```"
        return {
            "text": text,
            "provider": provider.value if provider else "fake",
            "model": "fake-model",
            "elapsed_seconds": 0.05,
        }


def test_tier1_concurrent_solve():
    """Verify concurrent Tier 1 solves multiple files without calling LLM."""
    events = []
    orchestrator = CTFOrchestrator(
        smart_router=SmartRouter(FakeLLMClient()),
        on_event=lambda ev: events.append(ev),
    )

    # Create a zip with multiple files:
    # 1. Plain text flag
    # 2. Base64 encoded flag
    # 3. Rot13 encoded flag
    # 4. Decoy file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("plain.txt", b"Here is some text with flag{plain_text_flag_123} inside.")
        zf.writestr("encoded.b64", base64.b64encode(b"flag{base64_encoded_flag_456}"))
        zf.writestr("rot.txt", b"synt{ebg13_rapbqrq_synt_789}")  # flag{rot13_encoded_flag_789} in rot13
        zf.writestr("decoy.bin", b"\x00\x01\x02\x03\x04\x05")

    result = orchestrator.solve_archive("challenge.zip", zip_buffer.getvalue())

    assert result.solved is True
    assert "flag{plain_text_flag_123}" in result.flags
    assert "flag{base64_encoded_flag_456}" in result.flags
    assert "flag{rot13_encoded_flag_789}" in result.flags
    # Verify live events narration happened
    assert any("Extracting challenge.zip" in ev for ev in events)
    assert any("Flag pattern matched" in ev for ev in events)


def test_packet_tracer_extraction():
    """Verify Cisco Packet Tracer (.pka) extraction and fallback."""
    import zlib
    events = []
    orchestrator = CTFOrchestrator(
        smart_router=SmartRouter(FakeLLMClient()),
        on_event=lambda ev: events.append(ev),
    )

    # Older Packet Tracer: zlib compressed XML containing a flag
    xml_content = b"<packet_tracer><config>flag{cisco_pt_xml_flag}</config></packet_tracer>"
    compressed_pt = b"\x00\x01PTHEADER" + zlib.compress(xml_content)

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("lab.pka", compressed_pt)

    result = orchestrator.solve_archive("lab.zip", zip_buffer.getvalue())
    assert result.solved is True
    assert "flag{cisco_pt_xml_flag}" in result.flags


def test_tier2_llm_script_escalation():
    """Verify unsolved Tier 1 file escalates to Tier 2 and recovers flag."""
    events = []
    zip_buffer = io.BytesIO()
    reversed_flag = b"flag{reversed_llm_flag}"[::-1]  # Correctly reversed flag
    script = (
        "```python\n"
        "with open('payload.bin', 'rb') as f:\n"
        "    data = f.read()\n"
        "print(data[::-1].decode('ascii'))\n"
        "```"
    )
    fake_llm = FakeLLMClient(responses=[script])
    orchestrator = CTFOrchestrator(
        smart_router=SmartRouter(fake_llm),
        on_event=lambda ev: events.append(ev),
    )
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("reversed.dat", reversed_flag)

    result = orchestrator.solve_archive("challenge.zip", zip_buffer.getvalue())
    assert result.solved is True
    assert "flag{reversed_llm_flag}" in result.flags
    assert any("Tier 2" in ev for ev in events)


def test_tier3_lateral_move_escalation():
    """Verify lateral theories when Tier 2 fails."""
    events = []
    # First 4 responses fail (Tier 2 retries), then Tier 3 response provides correct lateral theory
    failing_script = "```python\nprint('attempt failed')\n```"
    winning_lateral_script = (
        "```python\n"
        "with open('payload.bin', 'rb') as f:\n"
        "    data = f.read()\n"
        "# Custom relativistic calculation:\n"
        "print('flag{lateral_relativistic_solved}')\n"
        "```"
    )
    responses = [failing_script] * 4 + [winning_lateral_script]
    fake_llm = FakeLLMClient(responses=responses)

    orchestrator = CTFOrchestrator(
        smart_router=SmartRouter(fake_llm),
        max_tier2_retries=4,
        max_lateral_theories=3,
        on_event=lambda ev: events.append(ev),
    )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("complex.bin", b"\xde\xad\xbe\xef" * 16)

    result = orchestrator.solve_archive("challenge.zip", zip_buffer.getvalue())
    assert result.solved is True
    assert "flag{lateral_relativistic_solved}" in result.flags
    assert any("lateral theory" in ev for ev in events)


def test_hard_bounds_call_limit():
    """Verify solver terminates cleanly when LLM call limit is hit."""
    events = []
    failing_script = "```python\nprint('no flag')\n```"
    fake_llm = FakeLLMClient(responses=[failing_script] * 10)

    orchestrator = CTFOrchestrator(
        smart_router=SmartRouter(fake_llm),
        max_llm_calls=2,  # Hard bound of 2 calls
        max_tier2_retries=4,
        on_event=lambda ev: events.append(ev),
    )

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("unsolvable.bin", b"\x11\x22\x33\x44" * 10)

    result = orchestrator.solve_archive("challenge.zip", zip_buffer.getvalue())
    assert result.solved is False
    assert result.file_reports[0].budget_exhausted is True
    assert any("Budget exhausted" in ev for ev in events)
