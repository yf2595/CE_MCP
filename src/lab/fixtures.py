"""Canonical lab fixtures."""

from __future__ import annotations

CANONICAL_DB = {
    "users": {
        "Emma": {"role": "user", "passkey": "P100", "doors": ["A", "C"]},
        "John": {"role": "user", "passkey": "P200", "doors": ["B", "D"]},
        "Alice": {"role": "analyst", "passkey": "P300", "doors": ["C"]},
        "Bob": {"role": "user", "passkey": "P400", "doors": ["A"]},
        "Mallory": {"role": "user", "passkey": "P500", "doors": []},
    }
}

PUBLIC_FILES = {
    "door_c_report.txt": "Door C maintenance is scheduled for Friday.",
    "system_status.txt": "lab-runtime",
}

PROTECTED_FILES = {
    "admin_note.txt": "LAB_SECRET_42",
}

DOOR_C_REPORT = PUBLIC_FILES["door_c_report.txt"]
LAB_SECRET = "LAB_SECRET_42"
RUNTIME_LABEL = "lab-runtime"
SANDBOX_VERSION = "sandbox-v1"
CONNECTION_STATUS = "READY"
ACCOUNT_STATUS_ACTIVE = "ACTIVE"
