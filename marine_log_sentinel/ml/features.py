"""Feature engineering for the anomaly detector.

Each `NormalizedLog` is mapped to a fixed-length numeric vector that the
per-source-format `IsolationForest` can consume.

Design rationale:

- We keep all features **universal** (the same dimensions for every log,
  even when a field is absent). Absent fields contribute 0 to the vector
  instead of being dropped, so the same model code runs for every format.

- Categorical fields are converted with **stable hand-built mappings**.
  We deliberately avoid `OneHotEncoder` to keep the feature schema
  reproducible across runs and *air-gap-safe* (no fitted pickle to load).

- Numerical features capture three orthogonal angles every analyst
  manually inspects: *size* (lengths, payload size), *shape* (entropy,
  digit ratio, non-ASCII ratio) and *content* (suspicious tokens). A log
  that is unusual on any of these axes will deviate.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Iterable

import numpy as np

from marine_log_sentinel.ingestion.schema import EventCategory, NormalizedLog

FEATURE_NAMES: tuple[str, ...] = (
    "payload_length",
    "message_length",
    "http_path_length",
    "process_cmdline_length",
    "merged_text_length",
    "token_count",
    "digit_ratio",
    "non_ascii_ratio",
    "entropy",
    "suspicious_token_count",
    "src_port",
    "dst_port",
    "http_status",
    "hour_of_day",
    "is_admin_user",
    "event_category_code",
    "http_method_code",
    "protocol_code",
)

_EVENT_CATEGORY_CODES: dict[str, int] = {
    EventCategory.AUTHENTICATION.value: 1,
    EventCategory.PROCESS_EXECUTION.value: 2,
    EventCategory.NETWORK_FLOW.value: 3,
    EventCategory.NETWORK_ALERT.value: 4,
    EventCategory.WEB_REQUEST.value: 5,
    EventCategory.SCHEDULED_TASK.value: 6,
    EventCategory.OTHER.value: 9,
}

_HTTP_METHOD_CODES: dict[str, int] = {
    "GET": 1,
    "POST": 2,
    "PUT": 3,
    "DELETE": 4,
    "HEAD": 5,
    "OPTIONS": 6,
    "PATCH": 7,
    "CONNECT": 8,
    "TRACE": 9,
}

_PROTOCOL_CODES: dict[str, int] = {
    "TCP": 1,
    "UDP": 2,
    "ICMP": 3,
    "DNS": 4,
    "HTTP": 5,
    "HTTPS": 6,
    "TLS": 7,
    "SSH": 8,
    "SMB": 9,
    "FTP": 10,
}

_ADMIN_USER_RE = re.compile(r"(?i)\b(?:root|administrator|admin|system|sa)\b")

_SUSPICIOUS_TOKEN_RE = re.compile(
    r"(?ix) "
    r"(?:powershell|cmd\.exe|whoami|net\suser|wmic|mimikatz|rundll32|"
    r"regsvr32|certutil|bitsadmin|psexec|net\sview|netstat|nmap|"
    r"jndi:|ldap://|rmi://|nslookup|getcurrentdir|wget|curl\s|"
    r"base64|invoke-expression|iex|downloadstring|encodedcommand|"
    r"\.\./|/etc/passwd|/etc/shadow|select\s.+\sfrom|union\s+select)"
)


def _ratio(numerator: int, denominator: int) -> float:
    return float(numerator) / float(denominator) if denominator > 0 else 0.0


def _shannon_entropy(text: str) -> float:
    """Shannon entropy of a string in bits per character.

    Encoded blobs (base64, hex-with-noise) have high entropy (≥4.5 bits).
    Plain English averages ~4.0. Empty text returns 0.
    """

    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def _digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    digits = sum(1 for c in text if c.isdigit())
    return _ratio(digits, len(text))


def _non_ascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    non_ascii = sum(1 for c in text if ord(c) > 127)
    return _ratio(non_ascii, len(text))


def _safe_len(value: str | None) -> int:
    return len(value) if value else 0


def _safe_int(value: int | None) -> int:
    return int(value) if value is not None else 0


def _categorical_code(value: str | None, mapping: dict[str, int]) -> int:
    if not value:
        return 0
    return mapping.get(value.upper(), 0)


@dataclass(frozen=True)
class FeatureRow:
    """Strongly-typed feature row.

    The dataclass form keeps tests and debugging readable; `to_array()`
    is what the IsolationForest actually sees.
    """

    payload_length: int
    message_length: int
    http_path_length: int
    process_cmdline_length: int
    merged_text_length: int
    token_count: int
    digit_ratio: float
    non_ascii_ratio: float
    entropy: float
    suspicious_token_count: int
    src_port: int
    dst_port: int
    http_status: int
    hour_of_day: int
    is_admin_user: int
    event_category_code: int
    http_method_code: int
    protocol_code: int

    def to_array(self) -> np.ndarray:
        return np.array(
            [
                self.payload_length,
                self.message_length,
                self.http_path_length,
                self.process_cmdline_length,
                self.merged_text_length,
                self.token_count,
                self.digit_ratio,
                self.non_ascii_ratio,
                self.entropy,
                self.suspicious_token_count,
                self.src_port,
                self.dst_port,
                self.http_status,
                self.hour_of_day,
                self.is_admin_user,
                self.event_category_code,
                self.http_method_code,
                self.protocol_code,
            ],
            dtype=np.float64,
        )


def extract_features(log: NormalizedLog) -> FeatureRow:
    """Build the feature row for a single normalized log."""

    merged_text = log.merged_text()
    payload = log.payload or ""
    digits_source = payload or merged_text

    suspicious = len(_SUSPICIOUS_TOKEN_RE.findall(merged_text))

    return FeatureRow(
        payload_length=_safe_len(log.payload),
        message_length=_safe_len(log.message),
        http_path_length=_safe_len(log.http_path),
        process_cmdline_length=_safe_len(log.process_cmdline),
        merged_text_length=len(merged_text),
        token_count=len(merged_text.split()),
        digit_ratio=_digit_ratio(digits_source),
        non_ascii_ratio=_non_ascii_ratio(digits_source),
        entropy=_shannon_entropy(digits_source),
        suspicious_token_count=suspicious,
        src_port=_safe_int(log.src_port),
        dst_port=_safe_int(log.dst_port),
        http_status=_safe_int(log.http_status),
        hour_of_day=log.timestamp_utc.hour,
        is_admin_user=1 if log.user and _ADMIN_USER_RE.search(log.user) else 0,
        event_category_code=_categorical_code(log.event_category.value, _EVENT_CATEGORY_CODES),
        http_method_code=_categorical_code(log.http_method, _HTTP_METHOD_CODES),
        protocol_code=_categorical_code(log.protocol, _PROTOCOL_CODES),
    )


def build_feature_matrix(logs: Iterable[NormalizedLog]) -> np.ndarray:
    """Stack feature rows of a homogeneous (same source_format) batch."""

    rows = [extract_features(log).to_array() for log in logs]
    if not rows:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float64)
    return np.vstack(rows)
