"""Per-connector circuit breaker (Phase 2.2).

Rules:
- Opens after 5 consecutive failures.
- Transitions to half-open after 60 seconds.
- Closes on successful trial probe in half-open state.
- Re-opens immediately on failure in half-open state.
"""

from __future__ import annotations

import time
from typing import Optional
from redloop.connectors.models import CircuitState


class CircuitBreakerOpenError(Exception):
    """Raised when an operation is attempted on an open circuit breaker."""
    pass


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state: CircuitState = CircuitState.CLOSED
        self.failure_count: int = 0
        self.consecutive_successes: int = 0
        self.last_failure_time: Optional[float] = None
        self.opened_at: Optional[float] = None

    def can_execute(self) -> bool:
        """Determines whether a call can proceed through the circuit."""
        now = time.time()
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            if self.opened_at and (now - self.opened_at) >= self.recovery_timeout:
                self.state = CircuitState.HALF_OPEN
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            return True

        return False

    def record_success(self) -> None:
        """Records a successful operation and resets circuit state."""
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.opened_at = None
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0

    def record_failure(self) -> None:
        """Records a failed operation and trips the breaker if threshold is reached."""
        now = time.time()
        self.last_failure_time = now
        self.failure_count += 1

        if self.state == CircuitState.HALF_OPEN:
            # Immediate re-trip back to OPEN on trial probe failure
            self.state = CircuitState.OPEN
            self.opened_at = now
        elif self.state == CircuitState.CLOSED:
            if self.failure_count >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.opened_at = now

    def reset(self) -> None:
        """Manual reset of the circuit breaker."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.opened_at = None
        self.last_failure_time = None

