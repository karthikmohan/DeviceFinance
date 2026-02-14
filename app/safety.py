"""
Gate 4 — Safety Mechanisms

1. Circuit Breaker: prevents mass-lock scenarios
2. Canary Rollout: staged DPC update deployment
3. Emergency Mass Unlock: see /admin/emergency-unlock in main.py
"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("safety")


# ═══════════════════════════════════════════════════════════════════════
# 1. CIRCUIT BREAKER — Mass Lock Protection
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class CircuitBreaker:
    """
    Sliding-window circuit breaker for lock operations.

    Tracks the count of lock commands issued within a rolling time window.
    If the count exceeds `max_locks_in_window`, the breaker trips OPEN
    and all subsequent lock operations are blocked until manual reset
    or the cooldown expires.

    Parameters:
        max_locks_in_window: max lock commands allowed in the window
        window_seconds: size of the sliding window
        cooldown_seconds: auto-reset after this duration (0 = manual only)
    """

    max_locks_in_window: int = 50
    window_seconds: int = 300       # 5-minute window
    cooldown_seconds: int = 600     # 10-minute auto-reset

    _lock_timestamps: list[float] = field(default_factory=list)
    _tripped_at: float | None = field(default=None)
    _state: str = field(default="CLOSED")  # CLOSED | OPEN

    def allow_lock(self) -> bool:
        """Check if a lock operation is permitted."""
        self._maybe_auto_reset()

        if self._state == "OPEN":
            logger.warning("CIRCUIT_BREAKER | OPEN — lock denied")
            return False
        return True

    def record_lock(self) -> None:
        """Record a lock operation and trip if threshold exceeded."""
        now = time.time()
        self._lock_timestamps.append(now)

        # Trim timestamps outside the window
        cutoff = now - self.window_seconds
        self._lock_timestamps = [t for t in self._lock_timestamps if t > cutoff]

        if len(self._lock_timestamps) >= self.max_locks_in_window:
            self._trip()

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED."""
        self._state = "CLOSED"
        self._tripped_at = None
        self._lock_timestamps.clear()
        logger.info("CIRCUIT_BREAKER | Manually reset to CLOSED")

    @property
    def state(self) -> str:
        self._maybe_auto_reset()
        return self._state

    @property
    def current_count(self) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        return len([t for t in self._lock_timestamps if t > cutoff])

    def _trip(self) -> None:
        self._state = "OPEN"
        self._tripped_at = time.time()
        logger.critical(
            f"CIRCUIT_BREAKER | TRIPPED OPEN — "
            f"{len(self._lock_timestamps)} locks in {self.window_seconds}s window "
            f"(threshold: {self.max_locks_in_window})"
        )

    def _maybe_auto_reset(self) -> None:
        if (
            self._state == "OPEN"
            and self.cooldown_seconds > 0
            and self._tripped_at is not None
            and time.time() - self._tripped_at > self.cooldown_seconds
        ):
            logger.info("CIRCUIT_BREAKER | Auto-reset after cooldown")
            self.reset()


# Singleton instance used by the backend
circuit_breaker = CircuitBreaker()


# ═══════════════════════════════════════════════════════════════════════
# 2. CANARY ROLLOUT — Staged DPC Update Deployment
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class CanaryRollout:
    """
    Controls staged rollout of DPC app updates.

    Flow:
        1. New DPC version uploaded → assigned to canary group (1-5% of fleet)
        2. Monitor error rate and heartbeat loss for `observation_window`
        3. If error_rate < threshold → promote to next stage
        4. If error_rate >= threshold → auto-rollback

    Stages:    CANARY (1%) → STAGED (10%) → BROAD (50%) → GA (100%)
    """

    stages: list[dict] = field(default_factory=lambda: [
        {"name": "CANARY", "percent": 1, "observation_hours": 24},
        {"name": "STAGED", "percent": 10, "observation_hours": 24},
        {"name": "BROAD",  "percent": 50, "observation_hours": 12},
        {"name": "GA",     "percent": 100, "observation_hours": 0},
    ])
    error_rate_threshold: float = 0.02   # 2% error rate triggers rollback
    heartbeat_loss_threshold: float = 0.05  # 5% heartbeat loss triggers rollback

    _current_stage_index: int = field(default=0)
    _version: str = field(default="")
    _active: bool = field(default=False)

    def start_rollout(self, version: str) -> dict:
        """Begin a new canary rollout."""
        self._version = version
        self._current_stage_index = 0
        self._active = True
        stage = self.stages[0]
        logger.info(
            f"CANARY | Starting rollout of {version} at {stage['name']} ({stage['percent']}%)"
        )
        return {"version": version, "stage": stage["name"], "percent": stage["percent"]}

    def evaluate_and_advance(self, error_rate: float, heartbeat_loss_rate: float) -> dict:
        """
        Evaluate current stage health and either advance or rollback.
        Called by a scheduled job after the observation window.
        """
        if not self._active:
            return {"status": "no_active_rollout"}

        stage = self.stages[self._current_stage_index]

        if error_rate >= self.error_rate_threshold:
            return self._rollback(f"Error rate {error_rate:.2%} >= {self.error_rate_threshold:.2%}")

        if heartbeat_loss_rate >= self.heartbeat_loss_threshold:
            return self._rollback(
                f"Heartbeat loss {heartbeat_loss_rate:.2%} >= {self.heartbeat_loss_threshold:.2%}"
            )

        # Advance to next stage
        if self._current_stage_index < len(self.stages) - 1:
            self._current_stage_index += 1
            next_stage = self.stages[self._current_stage_index]
            logger.info(
                f"CANARY | {self._version} promoted to {next_stage['name']} ({next_stage['percent']}%)"
            )
            return {
                "status": "promoted",
                "version": self._version,
                "stage": next_stage["name"],
                "percent": next_stage["percent"],
            }
        else:
            self._active = False
            logger.info(f"CANARY | {self._version} reached GA — rollout complete")
            return {"status": "ga_complete", "version": self._version}

    def _rollback(self, reason: str) -> dict:
        stage = self.stages[self._current_stage_index]
        self._active = False
        logger.critical(
            f"CANARY | ROLLBACK {self._version} at {stage['name']} — reason: {reason}"
        )
        return {
            "status": "rolled_back",
            "version": self._version,
            "stage": stage["name"],
            "reason": reason,
        }

    @property
    def current_status(self) -> dict:
        if not self._active:
            return {"active": False}
        stage = self.stages[self._current_stage_index]
        return {
            "active": True,
            "version": self._version,
            "stage": stage["name"],
            "percent": stage["percent"],
        }


# Singleton instance
canary_rollout = CanaryRollout()
