"""Event schema shared by every data source, the detectors, the agent and the dashboard."""

from __future__ import annotations

EVENT_COLUMNS: list[str] = [
    "event_id",
    "source",
    "event_type",
    "user_id",
    "department",
    "role",
    "file_id",
    "file_type",
    "file_category",
    "file_department",
    "sensitivity",
    "timestamp",
    "action",
    "device_id",
    "bytes",
]

# A field the source does not record. Used instead of guessing a value.
UNKNOWN = "unknown"

EVENT_TYPES: list[str] = ["file", "device", "logon"]

SENSITIVITY_LEVELS: list[str] = ["public", "internal", "confidential", "restricted", UNKNOWN]
SENSITIVE_LEVELS: frozenset[str] = frozenset({"confidential", "restricted"})

FILE_ACTIONS: list[str] = ["view", "edit", "download", "print", "copy_to_usb", "upload_external", "delete"]
DEVICE_ACTIONS: list[str] = ["usb_connect", "usb_disconnect"]
LOGON_ACTIONS: list[str] = ["logon", "logoff"]
ACTIONS: list[str] = FILE_ACTIONS + DEVICE_ACTIONS + LOGON_ACTIONS

# Actions that move data off the managed file share.
TRANSFER_ACTIONS: frozenset[str] = frozenset({"download", "copy_to_usb", "upload_external"})

FILE_TYPES: list[str] = ["document", "text", "image", "archive", "executable", "other"]

LABEL_COLUMNS: list[str] = ["user_id", "scenario", "is_anomalous", "window_start", "window_end"]
