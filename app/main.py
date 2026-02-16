"""
Gate 3 — Minimal Backend Policy Flow

Endpoints:
    POST /event              — Accept payment / lifecycle events
    GET  /policy/{imei}      — Return current policy payload for device
    GET  /commands/{imei}     — Fetch pending commands (poll by DPC)
    POST /commands/{id}/ack   — Acknowledge a command
    GET  /audit/{imei}        — View audit trail for a device
    POST /admin/emergency-unlock — Gate 4: emergency mass unlock
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

app = FastAPI(title="Device Finance Policy Backend", version="0.1.0")

# ── In-memory stores (swap for DB in production) ──────────────────────

devices: dict[str, DeviceState] = {}         # imei -> current state
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
    logger.info(f"EVENT | imei={payload.imei} event={payload.event_type.value} actor={payload.actor} txn={payload.transaction_id} ip={client_ip}")

    # Idempotency check
    if payload.transaction_id and payload.transaction_id in processed_txns:
        logger.info(f"EVENT | DUPLICATE txn={payload.transaction_id} imei={payload.imei} — skipped")
        return {
            "status": "duplicate",
            "message": f"Transaction {payload.transaction_id} already processed",
        }

    imei = payload.imei
    current_state = devices.get(imei, DeviceState.PROVISIONING)

    # admin.decommission is valid from any state
    if payload.event_type == EventType.ADMIN_DECOMMISSION:
        new_state = DeviceState.DECOMMISSIONED
    else:
        key = (current_state, payload.event_type)
        if key not in VALID_TRANSITIONS:
            logger.warning(f"EVENT | REJECTED imei={imei} invalid transition: {current_state.value} + {payload.event_type.value}")
            raise HTTPException(
                status_code=409,
                detail=f"Invalid transition: {current_state.value} + {payload.event_type.value}",
            )
        new_state = VALID_TRANSITIONS[key]

    # Circuit breaker: check before applying lock transitions
    if new_state in (DeviceState.SOFT_LOCKED, DeviceState.HARD_LOCKED):
        if not circuit_breaker.allow_lock():
            logger.critical(f"EVENT | CIRCUIT_BREAKER_BLOCKED imei={imei} attempted {current_state.value} -> {new_state.value}")
            raise HTTPException(
                status_code=503,
                detail="Circuit breaker OPEN — lock operations halted. Contact on-call.",
            )
        circuit_breaker.record_lock()

    # Apply transition
    devices[imei] = new_state

    logger.info(f"TRANSITION | imei={imei} {current_state.value} -> {new_state.value} event={payload.event_type.value} actor={payload.actor}")

    # Audit
    record = AuditRecord(
        imei=imei,
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
            imei=imei,
            command=cmd,
            payload=POLICY_TEMPLATES.get(new_state, {}).get("restrictions", {}),
            created_at=datetime.now(timezone.utc),
        )
        command_queue.append(entry)
        logger.info(f"COMMAND | imei={imei} queued={cmd.value} id={entry.id}")

    if payload.transaction_id:
        processed_txns.add(payload.transaction_id)

    return {
        "status": "ok",
        "imei": imei,
        "from_state": current_state.value,
        "to_state": new_state.value,
        "event": payload.event_type.value,
    }


@app.get("/policy/{imei}", response_model=PolicyResponse)
def get_policy(imei: str):
    """Return the current policy payload for a device."""
    state = devices.get(imei)
    if state is None:
        logger.warning(f"POLICY | imei={imei} NOT_FOUND")
        raise HTTPException(status_code=404, detail=f"Device {imei} not found")

    template = POLICY_TEMPLATES.get(state, POLICY_TEMPLATES[DeviceState.ACTIVE])
    logger.info(f"POLICY | imei={imei} state={state.value} restrictions={template['restrictions']}")
    return PolicyResponse(
        imei=imei,
        device_state=state,
        **template,
    )


@app.get("/commands/{imei}")
def get_commands(imei: str):
    """Return pending (unacknowledged) commands for a device."""
    pending = [c for c in command_queue if c.imei == imei and not c.acknowledged]
    logger.info(f"COMMANDS | imei={imei} pending={len(pending)}")
    return {"imei": imei, "commands": [c.model_dump() for c in pending]}


@app.post("/commands/{command_id}/ack")
def ack_command(command_id: str):
    """Mark a command as acknowledged by the DPC."""
    for c in command_queue:
        if c.id == command_id:
            c.acknowledged = True
            logger.info(f"COMMAND_ACK | id={command_id} imei={c.imei} command={c.command.value}")
            return {"status": "ok", "command_id": command_id}
    raise HTTPException(status_code=404, detail="Command not found")


@app.get("/audit/{imei}")
def get_audit(imei: str):
    """Return the full audit trail for a device."""
    records = [r.model_dump() for r in audit_log if r.imei == imei]
    logger.info(f"AUDIT | imei={imei} records={len(records)}")
    return {"imei": imei, "records": records}


@app.post("/admin/emergency-unlock")
def emergency_unlock(reason: str = "emergency"):
    """
    Gate 4 — Emergency mass unlock.
    Transitions ALL locked devices to ACTIVE.
    """
    unlocked = []
    locked_states = {DeviceState.SOFT_LOCKED, DeviceState.HARD_LOCKED, DeviceState.SUSPENDED}

    for imei, state in list(devices.items()):
        if state in locked_states:
            old_state = state
            devices[imei] = DeviceState.ACTIVE
            audit_log.append(AuditRecord(
                imei=imei,
                from_state=old_state,
                to_state=DeviceState.ACTIVE,
                event=EventType.ADMIN_REINSTATE,
                actor=f"emergency:{reason}",
                timestamp=datetime.now(timezone.utc),
            ))
            unlocked.append(imei)
            logger.info(f"EMERGENCY_UNLOCK | imei={imei} {old_state.value} -> ACTIVE reason={reason}")

    circuit_breaker.reset()

    logger.warning(f"EMERGENCY_UNLOCK | total={len(unlocked)} reason={reason}")

    return {
        "status": "ok",
        "unlocked_count": len(unlocked),
        "unlocked_imeis": unlocked,
        "reason": reason,
    }


@app.get("/devices")
def list_devices():
    """List all registered devices and their current state."""
    device_list = [{"imei": imei, "state": state.value} for imei, state in devices.items()]
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
