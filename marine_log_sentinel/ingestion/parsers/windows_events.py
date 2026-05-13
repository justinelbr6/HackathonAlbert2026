"""Parser for the Windows events CSV file.

The sample file has an unusual shape: each data row is wrapped in one outer
pair of double quotes, while embedded fields use both `""` (CSV-style) and
`\"` (JSON-style) escape conventions for inner quotes. We strip the outer
wrapping, collapse the doubled-quote escapes, then re-parse the row with
the stdlib `csv` module configured to honour the backslash escape.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from marine_log_sentinel.ingestion.parsers._utils import parse_iso
from marine_log_sentinel.ingestion.parsers.base import BaseParser, ParserError
from marine_log_sentinel.ingestion.schema import EventCategory, NormalizedLog, SourceFormat

_EXPECTED_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "event_id",
    "event_source",
    "computer",
    "user",
    "process_name",
    "command_line",
    "parent_process_name",
    "ip_source",
    "ip_destination",
    "port",
    "protocol",
)


def _categorize(event_source: str) -> EventCategory:
    es = (event_source or "").lower()
    if "taskscheduler" in es:
        return EventCategory.SCHEDULED_TASK
    if "security-auditing" in es or "security" in es:
        return EventCategory.AUTHENTICATION
    if "sysmon" in es:
        return EventCategory.PROCESS_EXECUTION
    return EventCategory.OTHER


def _none_if_blank(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return None if cleaned in {"", "-"} else cleaned


def _int_or_none(value: str | None) -> int | None:
    cleaned = _none_if_blank(value)
    if cleaned is None:
        return None
    try:
        return int(cleaned)
    except ValueError:
        return None


class WindowsEventsParser(BaseParser):
    name = "windows_events"

    def parse(self, path: Path) -> Iterator[NormalizedLog]:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            return

        for line_no, raw_line in enumerate(lines[1:], start=2):
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue
            inner = line
            if inner.startswith('"') and inner.endswith('"'):
                inner = inner[1:-1].replace('""', '"')
            try:
                values = next(csv.reader([inner], escapechar="\\"))
            except StopIteration:  # pragma: no cover - csv reader is non-empty for non-empty inner
                raise ParserError(f"{path}:{line_no} unparseable row")
            padded = values + [""] * (len(_EXPECTED_COLUMNS) - len(values))
            row = dict(zip(_EXPECTED_COLUMNS, padded))

            ts = parse_iso(row["timestamp"])
            yield NormalizedLog(
                timestamp_utc=ts,
                source_format=SourceFormat.WINDOWS_EVENT,
                event_category=_categorize(row["event_source"]),
                source_file=str(path),
                raw=line,
                host=_none_if_blank(row["computer"]),
                user=_none_if_blank(row["user"]),
                event_id=_none_if_blank(row["event_id"]),
                process_name=_none_if_blank(row["process_name"]),
                process_cmdline=_none_if_blank(row["command_line"]),
                parent_process_name=_none_if_blank(row["parent_process_name"]),
                src_ip=_none_if_blank(row["ip_source"]),
                dst_ip=_none_if_blank(row["ip_destination"]),
                dst_port=_int_or_none(row["port"]),
                protocol=_none_if_blank(row["protocol"]),
            )
