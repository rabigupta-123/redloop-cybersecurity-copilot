import pytest

from redloop.ctf import CTFSimulator
from redloop.memory import EpisodicMemory


class FakeAudit:
    def __init__(self):
        self.entries = []

    def log(self, target, action, module, status, details=None, scope_entry=None):
        self.entries.append(
            (target, action, module, status, details or {}, scope_entry)
        )


def test_challenge_catalog_is_synthetic():
    challenges = CTFSimulator.list_challenges()

    assert {challenge.id for challenge in challenges} == {
        "rpc-confirmation",
        "rpc-decline",
    }
    assert all(challenge.synthetic_target.startswith("ctf://") for challenge in challenges)


def test_simulation_requires_explicit_confirmation():
    audit = FakeAudit()
    simulator = CTFSimulator(audit)
    challenge = simulator.get_challenge("rpc-confirmation")

    result = simulator.simulate(
        challenge.id, challenge.suggested_module, confirmed=False
    )

    assert result.status == "confirmation_required"
    assert result.job_id is None
    assert result.session_id is None
    assert result.flag is None
    assert audit.entries[0][3] == "blocked"


def test_confirmed_simulation_returns_only_synthetic_state():
    audit = FakeAudit()
    simulator = CTFSimulator(audit)
    challenge = simulator.get_challenge("rpc-confirmation")

    result = simulator.simulate(
        challenge.id, challenge.suggested_module, confirmed=True
    )

    assert result.status == "simulated_success"
    assert result.job_id == "sim-job-rpc-confirmation"
    assert result.session_id == "sim-session-rpc-confirmation"
    assert result.flag == "CTF{simulated_workflow_complete}"
    assert "no target was contacted" in result.message
    assert audit.entries[0][0] == challenge.synthetic_target
    assert audit.entries[0][3] == "success"


def test_decline_scenario_never_creates_job_or_session():
    simulator = CTFSimulator(FakeAudit())
    challenge = simulator.get_challenge("rpc-decline")

    result = simulator.simulate(
        challenge.id, challenge.suggested_module, confirmed=False
    )

    assert result.status == "declined"
    assert result.job_id is None
    assert result.session_id is None


def test_module_outside_synthetic_catalog_is_rejected():
    audit = FakeAudit()
    simulator = CTFSimulator(audit)

    with pytest.raises(ValueError, match="not part"):
        simulator.simulate("rpc-confirmation", "exploit/real_module", confirmed=True)

    assert audit.entries[0][3] == "blocked"


def test_simulator_outcomes_are_recorded_in_memory(tmp_path):
    memory = EpisodicMemory(tmp_path / "memory.sqlite")
    simulator = CTFSimulator(FakeAudit(), memory=memory)
    challenge = simulator.get_challenge("rpc-confirmation")

    simulator.simulate(challenge.id, challenge.suggested_module, confirmed=True)

    matches = memory.retrieve_similar(
        "CTF workflow confirmation gate",
        module="ctf_simulator",
    )
    assert len(matches) == 1
    assert matches[0].record.outcome == "success"
    assert matches[0].record.approach == "confirmed synthetic workflow"
