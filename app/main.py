"""
Gate 3 — Minimal Backend Policy Flow

Endpoints:
    POST /event                         — Accept payment / lifecycle events
    GET  /policy/{serial_number}        — Return current policy payload for device
    GET  /commands/{serial_number}      — Fetch pending commands (poll by DPC)
    POST /commands/{id}/ack             — Acknowledge a command
    GET  /audit/{serial_number}         — View audit trail for a device
    DELETE /device/{serial_number}      — Remove a device and its history
    GET  /devices                       — List all registered devices
    POST /admin/emergency-unlock        — Gate 4: emergency mass unlock
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request

from .models import (
    AuditRecord,
    CommandEntry,
    CommandType,
    DeviceState,
    EventPayload,
    EventType,
    PolicyResponse,
    VALID_TRANSITIONS,
)
from .safety import circuit_breaker

# ── Structured logging ─────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-5s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("dpc-backend")

app = FastAPI(title="Device Finance Policy Backend", version="0.2.0")

# ── In-memory stores (swap for DB in production) ──────────────────────

devices: dict[str, DeviceState] = {}         # serial_number -> current state
audit_log: list[AuditRecord] = []
command_queue: list[CommandEntry] = []
processed_txns: set[str] = set()             # idempotency set


# ── Policy templates per state ─────────────────────────────────────────

POLICY_TEMPLATES: dict[DeviceState, dict] = {
    DeviceState.ACTIVE: {
        "restrictions": {"no_usb": False, "no_camera": False, "no_install_apps": False},
        "lock_screen_message": "",
        "protected_packages": ["com.example.fintechapp"],
    },
    DeviceState.GRACE_PERIOD: {
        "restrictions": {"no_usb": False, "no_camera": False, "no_install_apps": False},
        "lock_screen_message": "Payment overdue. Please pay to avoid restrictions.",
        "protected_packages": ["com.example.fintechapp"],
    },
    DeviceState.SOFT_LOCKED: {
        "restrictions": {"no_usb": True, "no_camera": True, "no_install_apps": True},
        "lock_screen_message": "Device restricted due to missed payment. Pay now to restore access.",
        "protected_packages": ["com.example.fintechapp"],
    },
    DeviceState.HARD_LOCKED: {
        "restrictions": {"no_usb": True, "no_camera": True, "no_install_apps": True},
        "lock_screen_message": "Device locked. Contact support or make payment to unlock.",
        "protected_packages": ["com.example.fintechapp"],
    },
    DeviceState.SUSPENDED: {
        "restrictions": {"no_usb": True, "no_camera": True, "no_install_apps": True},
        "lock_screen_message": "Device suspended. Contact support.",
        "protected_packages": ["com.example.fintechapp"],
    },
    DeviceState.STOLEN_LOCKED: {
        "restrictions": {"no_usb": True, "no_camera": True, "no_install_apps": True},
        "lock_screen_message": "This device has been reported. Contact authorities.",
        "protected_packages": ["com.example.fintechapp"],
    },
    DeviceState.PAID_OFF: {
        "restrictions": {"no_usb": False, "no_camera": False, "no_install_apps": False},
        "lock_screen_message": "",
        "protected_packages": [],
    },
    DeviceState.PROVISIONING: {
        "restrictions": {"no_usb": True, "no_camera": False, "no_install_apps": True},
        "lock_screen_message": "Setup in progress.",
        "protected_packages": ["com.example.fintechapp"],
    },
    DeviceState.DECOMMISSIONED: {
        "restrictions": {},
        "lock_screen_message": "Device decommissioned.",
        "protected_packages": [],
    },
}


# ── Endpoints ──────────────────────────────────────────────────────────

@app.post("/event", status_code=200)
def handle_event(payload: EventPayload, request: Request):
    """
    Accept a payment or lifecycle event and transition device state.
    Idempotent: duplicate transaction_ids are no-ops.
    """
    client_ip = request.client.host if request.client else "unknown"
    sn = payload.serial_number
    logger.info(
        f"EVENT | serial={sn} event={payload.event_type.value} "
        f"actor={payload.actor} txn={payload.transaction_id} ip={client_ip}"
    )

    # Idempotency check
    if payload.transaction_id and payload.transaction_id in processed_txns:
        logger.info(f"EVENT | DUPLICATE txn={payload.transaction_id} serial={sn} — skipped")
        return {
            "status": "duplicate",
            "message": f"Transaction {payload.transaction_id} already processed",
        }

    current_state = devices.get(sn, DeviceState.PROVISIONING)

    # admin.decommission is valid from any state
    if payload.event_type == EventType.ADMIN_DECOMMISSION:
        new_state = DeviceState.DECOMMISSIONED
    else:
        key = (current_state, payload.event_type)
        if key not in VALID_TRANSITIONS:
            logger.warning(
                f"EVENT | REJECTED serial={sn} invalid transition: "
                f"{current_state.value} + {payload.event_type.value}"
            )
            raise HTTPException(
                status_code=409,
                detail=f"Invalid transition: {current_state.value} + {payload.event_type.value}",
            )
        new_state = VALID_TRANSITIONS[key]

    # Circuit breaker: check before applying lock transitions
    if new_state in (DeviceState.SOFT_LOCKED, DeviceState.HARD_LOCKED):
        if not circuit_breaker.allow_lock():
            logger.critical(
                f"EVENT | CIRCUIT_BREAKER_BLOCKED serial={sn} "
                f"attempted {current_state.value} -> {new_state.value}"
            )
            raise HTTPException(
                status_code=503,
                detail="Circuit breaker OPEN — lock operations halted. Contact on-call.",
            )
        circuit_breaker.record_lock()

    # Apply transition
    devices[sn] = new_state

    logger.info(
        f"TRANSITION | serial={sn} {current_state.value} -> {new_state.value} "
        f"event={payload.event_type.value} actor={payload.actor}"
    )

    # Audit
    record = AuditRecord(
        serial_number=sn,
        from_state=current_state,
        to_state=new_state,
        event=payload.event_type,
        actor=payload.actor,
        timestamp=datetime.now(timezone.utc),
        transaction_id=payload.transaction_id,
    )
    audit_log.append(record)

    # Enqueue command to device
    cmd = _state_to_command(new_state)
    if cmd:
        entry = CommandEntry(
            id=str(uuid.uuid4()),
            serial_number=sn,
            command=cmd,
            payload=POLICY_TEMPLATES.get(new_state, {}).get("restrictions", {}),
            created_at=datetime.now(timezone.utc),
        )
        command_queue.append(entry)
        logger.info(f"COMMAND | serial={sn} queued={cmd.value} id={entry.id}")

    if payload.transaction_id:
        processed_txns.add(payload.transaction_id)

    return {
        "status": "ok",
        "serial_number": sn,
        "from_state": current_state.value,
        "to_state": new_state.value,
        "event": payload.event_type.value,
    }


@app.get("/policy/{serial_number}", response_model=PolicyResponse)
def get_policy(serial_number: str):
    """Return the current policy payload for a device."""
    state = devices.get(serial_number)
    if state is None:
        logger.warning(f"POLICY | serial={serial_number} NOT_FOUND")
        raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")

    template = POLICY_TEMPLATES.get(state, POLICY_TEMPLATES[DeviceState.ACTIVE])
    logger.info(f"POLICY | serial={serial_number} state={state.value} restrictions={template['restrictions']}")
    return PolicyResponse(
        serial_number=serial_number,
        device_state=state,
        **template,
    )


@app.get("/commands/{serial_number}")
def get_commands(serial_number: str):
    """Return pending (unacknowledged) commands for a device."""
    pending = [c for c in command_queue if c.serial_number == serial_number and not c.acknowledged]
    logger.info(f"COMMANDS | serial={serial_number} pending={len(pending)}")
    return {"serial_number": serial_number, "commands": [c.model_dump() for c in pending]}


@app.post("/commands/{command_id}/ack")
def ack_command(command_id: str):
    """Mark a command as acknowledged by the DPC."""
    for c in command_queue:
        if c.id == command_id:
            c.acknowledged = True
            logger.info(f"COMMAND_ACK | id={command_id} serial={c.serial_number} command={c.command.value}")
            return {"status": "ok", "command_id": command_id}
    raise HTTPException(status_code=404, detail="Command not found")


@app.get("/audit/{serial_number}")
def get_audit(serial_number: str):
    """Return the full audit trail for a device."""
    records = [r.model_dump() for r in audit_log if r.serial_number == serial_number]
    logger.info(f"AUDIT | serial={serial_number} records={len(records)}")
    return {"serial_number": serial_number, "records": records}


@app.delete("/device/{serial_number}")
def delete_device(serial_number: str):
    """
    Remove a device and all its associated data (state, audit, commands).
    Use this to clean up test devices or decommissioned entries.
    """
    if serial_number not in devices:
        logger.warning(f"DELETE | serial={serial_number} NOT_FOUND")
        raise HTTPException(status_code=404, detail=f"Device {serial_number} not found")

    # Remove device state
    del devices[serial_number]

    # Remove audit records
    removed_audit = len([r for r in audit_log if r.serial_number == serial_number])
    audit_log[:] = [r for r in audit_log if r.serial_number != serial_number]

    # Remove commands
    removed_cmds = len([c for c in command_queue if c.serial_number == serial_number])
    command_queue[:] = [c for c in command_queue if c.serial_number != serial_number]

    logger.info(
        f"DELETE | serial={serial_number} removed audit_records={removed_audit} commands={removed_cmds}"
    )
    return {
        "status": "ok",
        "serial_number": serial_number,
        "removed_audit_records": removed_audit,
        "removed_commands": removed_cmds,
    }


@app.post("/admin/emergency-unlock")
def emergency_unlock(reason: str = "emergency"):
    """
    Gate 4 — Emergency mass unlock.
    Transitions ALL locked devices to ACTIVE.
    """
    unlocked = []
    locked_states = {DeviceState.SOFT_LOCKED, DeviceState.HARD_LOCKED, DeviceState.SUSPENDED}

    for sn, state in list(devices.items()):
        if state in locked_states:
            old_state = state
            devices[sn] = DeviceState.ACTIVE
            audit_log.append(AuditRecord(
                serial_number=sn,
                from_state=old_state,
                to_state=DeviceState.ACTIVE,
                event=EventType.ADMIN_REINSTATE,
                actor=f"emergency:{reason}",
                timestamp=datetime.now(timezone.utc),
            ))
            unlocked.append(sn)
            logger.info(f"EMERGENCY_UNLOCK | serial={sn} {old_state.value} -> ACTIVE reason={reason}")

    circuit_breaker.reset()

    logger.warning(f"EMERGENCY_UNLOCK | total={len(unlocked)} reason={reason}")

    return {
        "status": "ok",
        "unlocked_count": len(unlocked),
        "unlocked_devices": unlocked,
        "reason": reason,
    }


@app.get("/devices")
def list_devices():
    """List all registered devices and their current state."""
    device_list = [
        {"serial_number": sn, "state": state.value}
        for sn, state in devices.items()
    ]
    logger.info(f"DEVICES | total={len(device_list)}")
    return {"devices": device_list, "total": len(device_list)}


# ── Helpers ────────────────────────────────────────────────────────────

def _state_to_command(state: DeviceState) -> CommandType | None:
    """Map a device state to the command the DPC should execute."""
    mapping = {
        DeviceState.ACTIVE: CommandType.UNLOCK,
        DeviceState.GRACE_PERIOD: None,  # warning only, no device command
        DeviceState.SOFT_LOCKED: CommandType.LOCK,
        DeviceState.HARD_LOCKED: CommandType.LOCK,
        DeviceState.SUSPENDED: CommandType.LOCK,
        DeviceState.STOLEN_LOCKED: CommandType.LOCK,
        DeviceState.PAID_OFF: CommandType.UNLOCK,
        DeviceState.DECOMMISSIONED: CommandType.WIPE,
    }
    return mapping.get(state)
