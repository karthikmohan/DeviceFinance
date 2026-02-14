"""
Tests for the backend policy flow — validates state transitions,
idempotency, circuit breaker, and policy responses.
"""

from fastapi.testclient import TestClient

from app.main import app, devices, audit_log, command_queue, processed_txns
from app.models import DeviceState
from app.safety import circuit_breaker

client = TestClient(app)

IMEI = "123456789012345"


def _reset():
    devices.clear()
    audit_log.clear()
    command_queue.clear()
    processed_txns.clear()
    circuit_breaker.reset()


# ── State transition tests ─────────────────────────────────────────────

def test_enroll_device():
    _reset()
    resp = client.post("/event", json={
        "imei": IMEI,
        "event_type": "dpc.enrolled",
        "actor": "dpc",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["from_state"] == "PROVISIONING"
    assert data["to_state"] == "ACTIVE"


def test_payment_overdue_then_receive():
    _reset()
    # Enroll
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    assert devices[IMEI] == DeviceState.ACTIVE

    # Payment overdue
    client.post("/event", json={"imei": IMEI, "event_type": "payment.overdue"})
    assert devices[IMEI] == DeviceState.GRACE_PERIOD

    # Payment received
    client.post("/event", json={"imei": IMEI, "event_type": "payment.received"})
    assert devices[IMEI] == DeviceState.ACTIVE


def test_full_lock_escalation():
    _reset()
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    client.post("/event", json={"imei": IMEI, "event_type": "payment.overdue"})
    client.post("/event", json={"imei": IMEI, "event_type": "grace.expired"})
    assert devices[IMEI] == DeviceState.SOFT_LOCKED

    client.post("/event", json={"imei": IMEI, "event_type": "escalation.timeout"})
    assert devices[IMEI] == DeviceState.HARD_LOCKED


def test_invalid_transition_rejected():
    _reset()
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    # ACTIVE + grace.expired is invalid
    resp = client.post("/event", json={"imei": IMEI, "event_type": "grace.expired"})
    assert resp.status_code == 409


# ── Idempotency ────────────────────────────────────────────────────────

def test_idempotent_event():
    _reset()
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    resp1 = client.post("/event", json={
        "imei": IMEI, "event_type": "payment.overdue", "transaction_id": "txn-001"
    })
    assert resp1.status_code == 200
    assert resp1.json()["to_state"] == "GRACE_PERIOD"

    resp2 = client.post("/event", json={
        "imei": IMEI, "event_type": "payment.overdue", "transaction_id": "txn-001"
    })
    assert resp2.json()["status"] == "duplicate"


# ── Policy endpoint ────────────────────────────────────────────────────

def test_policy_active_device():
    _reset()
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    resp = client.get(f"/policy/{IMEI}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["device_state"] == "ACTIVE"
    assert data["restrictions"]["no_camera"] is False


def test_policy_locked_device():
    _reset()
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    client.post("/event", json={"imei": IMEI, "event_type": "payment.overdue"})
    client.post("/event", json={"imei": IMEI, "event_type": "grace.expired"})
    resp = client.get(f"/policy/{IMEI}")
    data = resp.json()
    assert data["device_state"] == "SOFT_LOCKED"
    assert data["restrictions"]["no_camera"] is True
    assert "payment" in data["lock_screen_message"].lower()


def test_policy_unknown_device_404():
    _reset()
    resp = client.get("/policy/999999999999999")
    assert resp.status_code == 404


# ── Audit trail ────────────────────────────────────────────────────────

def test_audit_trail():
    _reset()
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    client.post("/event", json={"imei": IMEI, "event_type": "payment.overdue"})
    resp = client.get(f"/audit/{IMEI}")
    records = resp.json()["records"]
    assert len(records) == 2
    assert records[0]["from_state"] == "PROVISIONING"
    assert records[1]["to_state"] == "GRACE_PERIOD"


# ── Command queue ──────────────────────────────────────────────────────

def test_command_queue_and_ack():
    _reset()
    client.post("/event", json={"imei": IMEI, "event_type": "dpc.enrolled"})
    resp = client.get(f"/commands/{IMEI}")
    commands = resp.json()["commands"]
    assert len(commands) >= 1
    cmd_id = commands[0]["id"]

    ack_resp = client.post(f"/commands/{cmd_id}/ack")
    assert ack_resp.json()["status"] == "ok"

    # After ack, no pending commands
    resp2 = client.get(f"/commands/{IMEI}")
    assert len(resp2.json()["commands"]) == 0


# ── Circuit breaker ───────────────────────────────────────────────────

def test_circuit_breaker_trips():
    _reset()
    circuit_breaker.max_locks_in_window = 3
    circuit_breaker.window_seconds = 300

    for i in range(3):
        imei = f"00000000000{i:04d}"
        devices[imei] = DeviceState.ACTIVE
        client.post("/event", json={"imei": imei, "event_type": "payment.overdue"})
        devices[imei] = DeviceState.GRACE_PERIOD
        client.post("/event", json={"imei": imei, "event_type": "grace.expired"})

    # Next lock should be blocked
    imei_blocked = "000000000009999"
    devices[imei_blocked] = DeviceState.GRACE_PERIOD
    resp = client.post("/event", json={"imei": imei_blocked, "event_type": "grace.expired"})
    assert resp.status_code == 503
    assert "circuit breaker" in resp.json()["detail"].lower()

    # Reset and restore default
    circuit_breaker.max_locks_in_window = 50


# ── Emergency unlock ──────────────────────────────────────────────────

def test_emergency_unlock():
    _reset()
    # Set up some locked devices
    for i in range(5):
        imei = f"11111111111{i:04d}"
        devices[imei] = DeviceState.HARD_LOCKED

    resp = client.post("/admin/emergency-unlock", params={"reason": "test-drill"})
    data = resp.json()
    assert data["unlocked_count"] == 5
    for imei in data["unlocked_imeis"]:
        assert devices[imei] == DeviceState.ACTIVE
