"""In-process CTF workflow simulator with synthetic targets and outcomes."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

from redloop.audit import AuditLogger
from redloop.memory import EpisodicMemory, MemoryRecord


class CTFChallenge(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    briefing: str
    synthetic_target: str
    suggested_module: str
    hint: str


class SimulatedExploitResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    challenge_id: str
    status: Literal["confirmation_required", "declined", "simulated_success"]
    job_id: str | None = None
    session_id: str | None = None
    message: str
    flag: str | None = None


CHALLENGES = (
    CTFChallenge(
        id="rpc-confirmation",
        title="The Confirmation Gate",
        briefing=(
            "Practice the search → review → human confirmation workflow. "
            "All module names, targets, jobs, and results in this exercise are "
            "fictional and handled in memory."
        ),
        synthetic_target="ctf://synthetic-confirmation-lab",
        suggested_module="training/simulated_check",
        hint="Review the suggested module, then explicitly confirm the simulation.",
    ),
    CTFChallenge(
        id="rpc-decline",
        title="Decline Safely",
        briefing=(
            "Practice declining a proposed simulated action. A declined action "
            "must not create a simulated job or session."
        ),
        synthetic_target="ctf://synthetic-decline-lab",
        suggested_module="training/simulated_check",
        hint="Run the simulation without confirmation and inspect its status.",
    ),
)

_CHALLENGE_BY_ID = {challenge.id: challenge for challenge in CHALLENGES}
_SIMULATED_FLAG = "CTF{simulated_workflow_complete}"


class CTFSimulator:
    """Simulate an exploit workflow without targets, sockets, or execution."""

    def __init__(
        self, audit: AuditLogger, memory: EpisodicMemory | None = None
    ):
        self.audit = audit
        self.memory = memory

    @staticmethod
    def list_challenges() -> list[CTFChallenge]:
        return list(CHALLENGES)

    @staticmethod
    def get_challenge(challenge_id: str) -> CTFChallenge:
        try:
            return _CHALLENGE_BY_ID[challenge_id]
        except KeyError as exc:
            raise ValueError(f"Unknown CTF challenge: {challenge_id}") from exc

    def simulate(
        self,
        challenge_id: str,
        module_name: str,
        confirmed: bool = False,
    ) -> SimulatedExploitResult:
        challenge = self.get_challenge(challenge_id)
        target = challenge.synthetic_target
        if module_name != challenge.suggested_module:
            self.audit.log(
                target,
                "ctf_simulate",
                "ctf_simulator",
                "blocked",
                {"reason": "module_not_in_synthetic_challenge_catalog"},
            )
            if self.memory:
                self.memory.store(
                    MemoryRecord(
                        task_description=f"CTF workflow: {challenge.title}",
                        approach="validate module against synthetic challenge catalog",
                        outcome="failure",
                        module="ctf_simulator",
                        details="module rejected",
                    )
                )
            raise ValueError("Module is not part of this synthetic challenge")

        if not confirmed:
            self.audit.log(
                target,
                "ctf_simulate",
                "ctf_simulator",
                "blocked",
                {"reason": "simulation_not_confirmed"},
            )
            if self.memory:
                self.memory.store(
                    MemoryRecord(
                        task_description=f"CTF workflow: {challenge.title}",
                        approach="confirmation required",
                        outcome="failure",
                        module="ctf_simulator",
                        details="simulation not confirmed",
                    )
                )
            status = (
                "declined" if challenge_id == "rpc-decline"
                else "confirmation_required"
            )
            return SimulatedExploitResult(
                challenge_id=challenge_id,
                status=status,
                message="No action was run; no job or session was created.",
            )

        result = SimulatedExploitResult(
            challenge_id=challenge_id,
            status="simulated_success",
            job_id=f"sim-job-{challenge_id}",
            session_id=f"sim-session-{challenge_id}",
            message="Synthetic simulation complete; no target was contacted.",
            flag=_SIMULATED_FLAG,
        )
        self.audit.log(
            target,
            "ctf_simulate",
            "ctf_simulator",
            "success",
            {
                "module": module_name,
                "job_id": result.job_id,
                "session_id": result.session_id,
            },
        )
        if self.memory:
            self.memory.store(
                MemoryRecord(
                    task_description=f"CTF workflow: {challenge.title}",
                    approach="confirmed synthetic workflow",
                    outcome="success",
                    module="ctf_simulator",
                    details="synthetic simulation completed",
                )
            )
        return result
