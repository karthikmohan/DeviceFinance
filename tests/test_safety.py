"""
Tests for Gate 4 safety mechanisms — circuit breaker and canary rollout.
"""

import time
from app.safety import CircuitBreaker, CanaryRollout


# ── Circuit Breaker Tests ──────────────────────────────────────────────

def test_cb_allows_under_threshold():
    cb = CircuitBreaker(max_locks_in_window=5, window_seconds=60)
    for _ in range(4):
        assert cb.allow_lock() is True
        cb.record_lock()
    assert cb.state == "CLOSED"


def test_cb_trips_at_threshold():
    cb = CircuitBreaker(max_locks_in_window=3, window_seconds=60)
    for _ in range(3):
        cb.record_lock()
    assert cb.state == "OPEN"
    assert cb.allow_lock() is False


def test_cb_manual_reset():
    cb = CircuitBreaker(max_locks_in_window=2, window_seconds=60)
    cb.record_lock()
    cb.record_lock()
    assert cb.state == "OPEN"
    cb.reset()
    assert cb.state == "CLOSED"
    assert cb.allow_lock() is True


def test_cb_auto_reset_after_cooldown():
    cb = CircuitBreaker(max_locks_in_window=1, window_seconds=60, cooldown_seconds=1)
    cb.record_lock()
    assert cb.state == "OPEN"
    time.sleep(1.1)
    assert cb.state == "CLOSED"


def test_cb_window_slides():
    cb = CircuitBreaker(max_locks_in_window=3, window_seconds=1)
    cb.record_lock()
    cb.record_lock()
    time.sleep(1.1)
    # Old timestamps should have expired
    cb.record_lock()
    assert cb.state == "CLOSED"
    assert cb.current_count == 1


# ── Canary Rollout Tests ──────────────────────────────────────────────

def test_canary_start():
    cr = CanaryRollout()
    result = cr.start_rollout("2.0.0")
    assert result["stage"] == "CANARY"
    assert result["percent"] == 1


def test_canary_promote_through_stages():
    cr = CanaryRollout()
    cr.start_rollout("2.0.0")

    # Healthy metrics → promote CANARY → STAGED
    result = cr.evaluate_and_advance(error_rate=0.001, heartbeat_loss_rate=0.01)
    assert result["status"] == "promoted"
    assert result["stage"] == "STAGED"
    assert result["percent"] == 10

    # Promote STAGED → BROAD
    result = cr.evaluate_and_advance(error_rate=0.005, heartbeat_loss_rate=0.02)
    assert result["status"] == "promoted"
    assert result["stage"] == "BROAD"

    # Promote BROAD → GA
    result = cr.evaluate_and_advance(error_rate=0.01, heartbeat_loss_rate=0.03)
    assert result["status"] == "promoted"
    assert result["stage"] == "GA"
    assert result["percent"] == 100

    # Evaluate at GA → complete
    result = cr.evaluate_and_advance(error_rate=0.005, heartbeat_loss_rate=0.01)
    assert result["status"] == "ga_complete"


def test_canary_rollback_on_high_error_rate():
    cr = CanaryRollout()
    cr.start_rollout("2.1.0")

    result = cr.evaluate_and_advance(error_rate=0.05, heartbeat_loss_rate=0.01)
    assert result["status"] == "rolled_back"
    assert "error rate" in result["reason"].lower()


def test_canary_rollback_on_heartbeat_loss():
    cr = CanaryRollout()
    cr.start_rollout("2.2.0")

    result = cr.evaluate_and_advance(error_rate=0.001, heartbeat_loss_rate=0.10)
    assert result["status"] == "rolled_back"
    assert "heartbeat" in result["reason"].lower()


def test_canary_no_active_rollout():
    cr = CanaryRollout()
    result = cr.evaluate_and_advance(error_rate=0.0, heartbeat_loss_rate=0.0)
    assert result["status"] == "no_active_rollout"
