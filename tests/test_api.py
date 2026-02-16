"""
Tests for the backend policy flow — validates state transitions,
idempotency, circuit breaker, policy responses, and device deletion.
"""

from fastapi.testclient import TestClient

from app.main import app, devices, audit_log, command_queue, confirmations, processed_txns
from app.models import DeviceState
from app.safety import circuit_breaker

client = TestClient(app)

SERIAL = "EMULATOR30X1234"


def _reset():
    devices.clear()
    audit_log.clear()
    command_queue.clear()
    confirmations.clear()
    processed_txns.clear()
    circuit_breaker.reset()


# ── State transition tests ─────────────────────────────────────────────

def test_enroll_device():
    _reset()
    resp = client.post("/api/event", json={
        "serial_number": SERIAL,
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
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    assert devices[SERIAL] == DeviceState.ACTIVE

    # Payment overdue
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "payment.overdue"})
    assert devices[SERIAL] == DeviceState.GRACE_PERIOD

    # Payment received
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "payment.received"})
    assert devices[SERIAL] == DeviceState.ACTIVE


def test_full_lock_escalation():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "payment.overdue"})
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "grace.expired"})
    assert devices[SERIAL] == DeviceState.SOFT_LOCKED

    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "escalation.timeout"})
    assert devices[SERIAL] == DeviceState.HARD_LOCKED


def test_invalid_transition_rejected():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    # ACTIVE + grace.expired is invalid
    resp = client.post("/api/event", json={"serial_number": SERIAL, "event_type": "grace.expired"})
    assert resp.status_code == 409


# ── Idempotency ────────────────────────────────────────────────────────

def test_idempotent_event():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    resp1 = client.post("/api/event", json={
        "serial_number": SERIAL, "event_type": "payment.overdue", "transaction_id": "txn-001"
    })
    assert resp1.status_code == 200
    assert resp1.json()["to_state"] == "GRACE_PERIOD"

    resp2 = client.post("/api/event", json={
        "serial_number": SERIAL, "event_type": "payment.overdue", "transaction_id": "txn-001"
    })
    assert resp2.json()["status"] == "duplicate"


# ── Policy endpoint ────────────────────────────────────────────────────

def test_policy_active_device():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    resp = client.get(f"/api/policy/{SERIAL}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["device_state"] == "ACTIVE"
    assert data["restrictions"]["no_camera"] is False


def test_policy_locked_device():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "payment.overdue"})
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "grace.expired"})
    resp = client.get(f"/api/policy/{SERIAL}")
    data = resp.json()
    assert data["device_state"] == "SOFT_LOCKED"
    assert data["restrictions"]["no_camera"] is True
    assert "payment" in data["lock_screen_message"].lower()


def test_policy_unknown_device_404():
    _reset()
    resp = client.get("/api/policy/UNKNOWN_SERIAL_999")
    assert resp.status_code == 404


# ── Audit trail ────────────────────────────────────────────────────────

def test_audit_trail():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "payment.overdue"})
    resp = client.get(f"/api/audit/{SERIAL}")
    records = resp.json()["records"]
    assert len(records) == 2
    assert records[0]["from_state"] == "PROVISIONING"
    assert records[1]["to_state"] == "GRACE_PERIOD"


# ── Command queue ──────────────────────────────────────────────────────

def test_command_queue_and_ack():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    resp = client.get(f"/api/commands/{SERIAL}")
    commands = resp.json()["commands"]
    assert len(commands) >= 1
    cmd_id = commands[0]["id"]

    ack_resp = client.post(f"/api/commands/{cmd_id}/ack")
    assert ack_resp.json()["status"] == "ok"

    # After ack, no pending commands
    resp2 = client.get(f"/api/commands/{SERIAL}")
    assert len(resp2.json()["commands"]) == 0


# ── Circuit breaker ───────────────────────────────────────────────────

def test_circuit_breaker_trips():
    _reset()
    circuit_breaker.max_locks_in_window = 3
    circuit_breaker.window_seconds = 300

    for i in range(3):
        sn = f"CB_TEST_{i:04d}"
        devices[sn] = DeviceState.ACTIVE
        client.post("/api/event", json={"serial_number": sn, "event_type": "payment.overdue"})
        devices[sn] = DeviceState.GRACE_PERIOD
        client.post("/api/event", json={"serial_number": sn, "event_type": "grace.expired"})

    # Next lock should be blocked
    sn_blocked = "CB_TEST_BLOCKED"
    devices[sn_blocked] = DeviceState.GRACE_PERIOD
    resp = client.post("/api/event", json={"serial_number": sn_blocked, "event_type": "grace.expired"})
    assert resp.status_code == 503
    assert "circuit breaker" in resp.json()["detail"].lower()

    # Reset and restore default
    circuit_breaker.max_locks_in_window = 50


# ── Emergency unlock ──────────────────────────────────────────────────

def test_emergency_unlock():
    _reset()
    # Set up some locked devices
    for i in range(5):
        sn = f"EMERG_TEST_{i:04d}"
        devices[sn] = DeviceState.HARD_LOCKED

    resp = client.post("/api/admin/emergency-unlock", params={"reason": "test-drill"})
    data = resp.json()
    assert data["unlocked_count"] == 5
    for sn in data["unlocked_devices"]:
        assert devices[sn] == DeviceState.ACTIVE


# ── Device deletion ──────────────────────────────────────────────────

def test_delete_device():
    _reset()
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "dpc.enrolled"})
    client.post("/api/event", json={"serial_number": SERIAL, "event_type": "payment.overdue"})

    resp = client.delete(f"/api/device/{SERIAL}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["removed_audit_records"] == 2

    # Device should no longer exist
    assert SERIAL not in devices
    resp2 = client.get(f"/api/policy/{SERIAL}")
    assert resp2.status_code == 404


def test_delete_nonexistent_device():
    _reset()
    resp = client.delete("/api/device/DOES_NOT_EXIST")
    assert resp.status_code == 404


# ── Policy confirmation ──────────────────────────────────────────────

def test_confirm_policy():
    _reset()
    resp = client.post("/api/confirm", json={
        "serial_number": SERIAL,
        "previous_state": "SOFT_LOCKED",
        "new_state": "ACTIVE",
        "success": True,
        "details": "All restrictions cleared",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["success"] is True

    # Check confirmations endpoint
    resp2 = client.get(f"/api/confirmations/{SERIAL}")
    assert len(resp2.json()["confirmations"]) == 1


# ── Dashboard ────────────────────────────────────────────────────────

def test_dashboard_serves_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Device Finance Platform" in resp.text


# ── Transitions endpoint ──────────────────────────────────────────────

def test_transitions():
    resp = client.get("/api/transitions")
    assert resp.status_code == 200
    data = resp.json()
    assert "ACTIVE" in data
    assert any(t["event"] == "payment.overdue" for t in data["ACTIVE"])
