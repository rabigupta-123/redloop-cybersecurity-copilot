import json
from types import SimpleNamespace

import pytest

from redloop.executor import (
    ExecutionFailedError,
    SelfHealingExecutor,
)
from redloop.llm import Provider
from redloop.memory import EpisodicMemory, MemoryRecord
from redloop.scope import UnauthorizedTargetError


class FakeLLM:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.settings = SimpleNamespace(allow_cloud_routing=False)

    def is_provider_configured(self, provider):
        return provider == Provider.OLLAMA

    def complete(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, kwargs))
        return {
            "text": next(self.responses),
            "provider": kwargs["provider"].value,
            "elapsed_seconds": 0.0,
        }


class FakeAudit:
    def __init__(self):
        self.entries = []

    def log(self, target, action, module, status, details=None, scope_entry=None):
        self.entries.append(
            {
                "target": target,
                "action": action,
                "module": module,
                "status": status,
                "details": details or {},
                "scope_entry": scope_entry,
            }
        )


class FakeScope:
    def __init__(self, entry=None, error=None):
        self.entry = entry or SimpleNamespace(label="test-lab")
        self.error = error

    def check(self, target, action):
        if self.error:
            raise self.error
        return self.entry


def make_executor(responses, max_retries=3, scope=None):
    llm = FakeLLM(responses)
    audit = FakeAudit()
    executor = SelfHealingExecutor(
        llm=llm,
        audit=audit,
        scope=scope or FakeScope(),
        max_retries=max_retries,
    )
    return executor, llm, audit


def test_retries_with_prior_error_and_returns_result():
    executor, llm, audit = make_executor(
        [
            '{"operation":"divide_numbers","arguments":{"dividend":100,"divisors":[5,0]}}',
            '{"operation":"divide_numbers","arguments":{"dividend":100,"divisors":[5,2]}}',
        ]
    )

    report = executor.run("Divide 100 by 5 and 2", "192.168.56.10")

    assert report.success
    assert report.result == [20, 50]
    assert len(report.attempts) == 2
    assert "ZeroDivisionError" in report.attempts[0].error
    repair_history = json.loads(
        llm.calls[1][1].split("Prior requests and errors:\n", 1)[1]
    )
    assert repair_history[0]["response"] == report.attempts[0].response
    assert "cannot divide by zero" in llm.calls[1][1]
    assert [entry["status"] for entry in audit.entries] == [
        "started",
        "failed",
        "started",
        "success",
    ]
    assert all(entry["scope_entry"] == "test-lab" for entry in audit.entries)


def test_unknown_operation_is_rejected_and_retried():
    executor, _, _ = make_executor(
        [
            '{"operation":"run_shell","arguments":{"command":"whoami"}}',
            '{"operation":"parse_json","arguments":{"text":"{\\"ok\\":true}"}}',
        ]
    )

    report = executor.run("Parse the provided JSON", "192.168.56.10")

    assert report.result == {"ok": True}
    assert len(report.attempts) == 2
    assert "Input should be" in report.attempts[0].error or "literal_error" in report.attempts[0].error


def test_out_of_scope_is_rejected_before_llm_call():
    denial = UnauthorizedTargetError("not in scope")
    executor, llm, audit = make_executor([], scope=FakeScope(error=denial))

    with pytest.raises(UnauthorizedTargetError, match="not in scope"):
        executor.run("parse JSON", "8.8.8.8")

    assert llm.calls == []
    assert len(audit.entries) == 1
    assert audit.entries[0]["status"] == "blocked"


def test_exhaustion_preserves_attempts_and_logs_failure():
    executor, _, audit = make_executor(
        ["not json", "still not json"], max_retries=2
    )

    with pytest.raises(ExecutionFailedError) as exc_info:
        executor.run("parse JSON", "192.168.56.10")

    assert len(exc_info.value.attempts) == 2
    assert audit.entries[-1]["status"] == "failed"
    assert audit.entries[-1]["details"]["reason"] == "max_retries_exhausted"


@pytest.mark.parametrize("retries", [0, -1, 6, True])
def test_retry_count_is_bounded(retries):
    with pytest.raises(ValueError, match="max_retries"):
        SelfHealingExecutor(FakeLLM([]), FakeAudit(), FakeScope(), retries)


def test_memory_is_retrieved_after_scope_and_written_on_success(tmp_path):
    memory = EpisodicMemory(tmp_path / "memory.sqlite")
    memory.store(
        MemoryRecord(
            task_description="parse JSON input safely",
            approach="parse_json",
            outcome="success",
            module="executor",
        )
    )
    llm = FakeLLM(
        ['{"operation":"parse_json","arguments":{"text":"{\\"ok\\":true}"}}']
    )
    executor = SelfHealingExecutor(
        llm=llm,
        audit=FakeAudit(),
        scope=FakeScope(),
        memory=memory,
    )

    report = executor.run("parse JSON input", "192.168.56.10")

    assert report.result == {"ok": True}
    assert "Advisory local-operation history" in llm.calls[0][1]
    assert '"validated_operation": "parse_json"' in llm.calls[0][1]
    matches = memory.retrieve_similar("parse JSON input", module="executor")
    assert len(matches) == 2
