import pytest

from redloop.memory import EpisodicMemory, MemoryRecord


class FakeAudit:
    def __init__(self):
        self.entries = []

    def log(self, target, action, module, status, details=None, scope_entry=None):
        self.entries.append((target, action, module, status, details or {}))


def test_records_persist_and_recall_similar_tasks(tmp_path):
    db_path = tmp_path / "memory.sqlite"
    audit = FakeAudit()
    memory = EpisodicMemory(db_path, audit)
    first_id = memory.store(
        MemoryRecord(
            task_description="divide numbers with zero handling",
            approach="divide_numbers",
            outcome="success",
            module="executor",
            details="validated local operation succeeded",
        )
    )
    memory.store(
        MemoryRecord(
            task_description="static file metadata analysis",
            approach="hash and entropy",
            outcome="success",
            module="forensics",
        )
    )

    reloaded = EpisodicMemory(db_path)
    matches = reloaded.retrieve_similar(
        "divide numbers and handle zero", module="executor"
    )

    assert first_id > 0
    assert len(matches) == 1
    assert matches[0].record.approach == "divide_numbers"
    assert matches[0].similarity > 0
    assert len(audit.entries) == 2


def test_memory_filters_by_module_and_orders_by_similarity(tmp_path):
    memory = EpisodicMemory(tmp_path / "memory.sqlite")
    memory.store(
        MemoryRecord(
            task_description="parse json input",
            approach="parse_json",
            outcome="success",
            module="executor",
        )
    )
    memory.store(
        MemoryRecord(
            task_description="inspect local web response headers",
            approach="single scoped GET",
            outcome="success",
            module="webapp",
        )
    )

    assert memory.retrieve_similar("parse json", module="webapp") == []
    matches = memory.retrieve_similar("parse json input")
    assert matches[0].record.module == "executor"


@pytest.mark.parametrize(
    ("task", "module", "limit"),
    [
        ("", None, 3),
        ("x" * 1_001, None, 3),
        ("valid task", "invalid_module", 3),
        ("valid task", None, 0),
        ("valid task", None, 11),
    ],
)
def test_memory_queries_validate_bounds(tmp_path, task, module, limit):
    memory = EpisodicMemory(tmp_path / "memory.sqlite")

    with pytest.raises(ValueError):
        memory.retrieve_similar(task, module=module, n_results=limit)


def test_memory_rejects_code_and_unrecognized_modules(tmp_path):
    memory = EpisodicMemory(tmp_path / "memory.sqlite")
    with pytest.raises(ValueError):
        MemoryRecord(
            task_description="run code",
            approach="print(secret)",
            outcome="success",
            module="executor",
        )
