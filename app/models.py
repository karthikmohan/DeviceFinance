"""
Gate 3 — Data models and deterministic state machine.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────────

class DeviceState(str, Enum):
    PROVISIONING = "PROVISIONING"
    ACTIVE = "ACTIVE"
    GRACE_PERIOD = "GRACE_PERIOD"
    SOFT_LOCKED = "SOFT_LOCKED"
    HARD_LOCKED = "HARD_LOCKED"
    SUSPENDED = "SUSPENDED"
    PAID_OFF = "PAID_OFF"
    STOLEN_LOCKED = "STOLEN_LOCKED"
    DECOMMISSIONED = "DECOMMISSIONED"


class EventType(str, Enum):
    DPC_ENROLLED = "dpc.enrolled"
    PAYMENT_RECEIVED = "payment.received"
    PAYMENT_OVERDUE = "payment.overdue"
    PAYMENT_COMPLETED = "payment.completed"
    GRACE_EXPIRED = "grace.expired"
    ESCALATION_TIMEOUT = "escalation.timeout"
    ADMIN_SUSPEND = "admin.suspend"
    ADMIN_REINSTATE = "admin.reinstate"
    ADMIN_REPORT_STOLEN = "admin.report_stolen"
    ADMIN_RECOVER = "admin.recover"
    ADMIN_DECOMMISSION = "admin.decommission"
    PROVISIONING_FAILED = "provisioning.failed"


class CommandType(str, Enum):
    LOCK = "LOCK"
    UNLOCK = "UNLOCK"
    WIPE = "WIPE"
    SET_RESTRICTIONS = "SET_RESTRICTIONS"


# ── Valid state transitions ────────────────────────────────────────────

VALID_TRANSITIONS: dict[tuple[DeviceState, EventType], DeviceState] = {
    (DeviceState.PROVISIONING, EventType.DPC_ENROLLED): DeviceState.ACTIVE,
    (DeviceState.PROVISIONING, EventType.PROVISIONING_FAILED): DeviceState.DECOMMISSIONED,

    (DeviceState.ACTIVE, EventType.PAYMENT_OVERDUE): DeviceState.GRACE_PERIOD,
    (DeviceState.ACTIVE, EventType.PAYMENT_COMPLETED): DeviceState.PAID_OFF,
    (DeviceState.ACTIVE, EventType.ADMIN_SUSPEND): DeviceState.SUSPENDED,
    (DeviceState.ACTIVE, EventType.ADMIN_REPORT_STOLEN): DeviceState.STOLEN_LOCKED,

    (DeviceState.GRACE_PERIOD, EventType.PAYMENT_RECEIVED): DeviceState.ACTIVE,
    (DeviceState.GRACE_PERIOD, EventType.GRACE_EXPIRED): DeviceState.SOFT_LOCKED,

    (DeviceState.SOFT_LOCKED, EventType.PAYMENT_RECEIVED): DeviceState.ACTIVE,
    (DeviceState.SOFT_LOCKED, EventType.ESCALATION_TIMEOUT): DeviceState.HARD_LOCKED,

    (DeviceState.HARD_LOCKED, EventType.PAYMENT_RECEIVED): DeviceState.ACTIVE,
    (DeviceState.HARD_LOCKED, EventType.ADMIN_SUSPEND): DeviceState.SUSPENDED,
    (DeviceState.HARD_LOCKED, EventType.ADMIN_REPORT_STOLEN): DeviceState.STOLEN_LOCKED,

    (DeviceState.SUSPENDED, EventType.ADMIN_REINSTATE): DeviceState.ACTIVE,

    (DeviceState.STOLEN_LOCKED, EventType.ADMIN_RECOVER): DeviceState.SUSPENDED,
}

# admin.decommission is valid from any state — handled specially in the engine.


# ── Request / Response schemas ─────────────────────────────────────────

class EventPayload(BaseModel):
    serial_number: str = Field(..., min_length=1, max_length=64)
    event_type: EventType
    transaction_id: Optional[str] = None  # for idempotency
    actor: str = "system"
    metadata: dict = Field(default_factory=dict)


class PolicyResponse(BaseModel):
    serial_number: str
    device_state: DeviceState
    restrictions: dict
    lock_screen_message: str
    protected_packages: list[str]


class CommandEntry(BaseModel):
    id: str
    serial_number: str
    command: CommandType
    payload: dict = Field(default_factory=dict)
    created_at: datetime
    acknowledged: bool = False


class AuditRecord(BaseModel):
    serial_number: str
    from_state: DeviceState
    to_state: DeviceState
    event: EventType
    actor: str
    timestamp: datetime
    transaction_id: Optional[str] = None


class PolicyConfirmation(BaseModel):
    serial_number: str = Field(..., min_length=1, max_length=64)
    previous_state: str
    new_state: str
    success: bool
    details: str = ""
