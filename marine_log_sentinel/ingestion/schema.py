"""Unified log schema (Étape 1).

Inspired by OCSF / Elastic Common Schema. Every downstream layer of the
pipeline (ML, scoring, reporting) consumes instances of `NormalizedLog` and
nothing else. Source-format-specific knowledge stays in the parsers.

Pydantic v2 enforces field types at construction time: a malformed parser
output is rejected explicitly rather than silently propagating bad data
into the ML layer. The original record is always preserved verbatim in
`raw` so that an analyst can audit any downstream decision back to source.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class SourceFormat(str, Enum):
    APACHE_ACCESS = "apache_access"
    SURICATA_EVE = "suricata_eve"
    WINDOWS_SYSMON = "windows_sysmon"
    WINDOWS_EVENT = "windows_event"
    LINUX_SYSLOG = "linux_syslog"
    NETWORK_TRAFFIC = "network_traffic"


class EventCategory(str, Enum):
    PROCESS_EXECUTION = "process_execution"
    SCHEDULED_TASK = "scheduled_task"
    WEB_REQUEST = "web_request"
    NETWORK_FLOW = "network_flow"
    NETWORK_ALERT = "network_alert"
    AUTHENTICATION = "authentication"
    OTHER = "other"


class NormalizedLog(BaseModel):
    """One log record, normalized for downstream consumption."""

    model_config = ConfigDict(extra="forbid")

    # --- Core (always present) ---
    timestamp_utc: datetime
    source_format: SourceFormat
    event_category: EventCategory
    source_file: str
    raw: str = Field(..., description="Verbatim original record, preserved for audit.")

    # --- Host & identity ---
    host: Optional[str] = None
    user: Optional[str] = None

    # --- Process ---
    event_id: Optional[str] = None
    process_name: Optional[str] = None
    process_cmdline: Optional[str] = None
    parent_process_name: Optional[str] = None

    # --- Network ---
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None

    # --- Web / HTTP ---
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_user_agent: Optional[str] = None
    http_request: Optional[str] = None

    # --- Payload / message ---
    payload: Optional[str] = None
    message: Optional[str] = None

    # --- Source-emitted signature (e.g. Suricata alert) ---
    signature: Optional[str] = None
    signature_severity: Optional[str] = None

    def merged_text(self) -> str:
        """Concatenated free text useful for the NLP retrieval layer (Étape 3)."""

        parts = (
            self.process_cmdline,
            self.payload,
            self.http_user_agent,
            self.http_path,
            self.http_request,
            self.message,
            self.signature,
        )
        return " | ".join(part for part in parts if part)
