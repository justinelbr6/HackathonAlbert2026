"""Parser for the network traffic capture.

The challenge file `sample_logs_network_traffic.csv.xlsx` is a real Excel
workbook, but it stores the data as a single column whose values are
CSV-formatted strings (header included). We read it with openpyxl, then
re-parse each cell with the stdlib `csv` module.
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
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "payload",
    "http_user_agent",
    "http_request",
)


def _none_if_blank(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().strip('"')
    return None if cleaned in {"", "-"} else cleaned


def _int_or_none(value: str | None) -> int | None:
    cleaned = _none_if_blank(value)
    if cleaned is None:
        return None
    try:
        return int(cleaned)
    except ValueError:
        return None


class NetworkTrafficParser(BaseParser):
    name = "network_traffic"

    def parse(self, path: Path) -> Iterator[NormalizedLog]:
        try:
            import openpyxl
        except ImportError as exc:  # pragma: no cover
            raise ParserError("openpyxl is required to read .xlsx files") from exc

        workbook = openpyxl.load_workbook(filename=str(path), read_only=True, data_only=True)
        try:
            sheet = workbook.active
            csv_rows: list[str] = []
            for row in sheet.iter_rows(values_only=True):
                if not row:
                    continue
                cell = row[0]
                if cell is None:
                    continue
                csv_rows.append(str(cell))
        finally:
            workbook.close()

        if not csv_rows:
            return

        header = next(csv.reader([csv_rows[0]]))
        if tuple(field.strip().lower() for field in header) != _EXPECTED_COLUMNS:
            raise ParserError(
                f"{path}: unexpected header {header}, expected {list(_EXPECTED_COLUMNS)}"
            )

        for line_no, line in enumerate(csv_rows[1:], start=2):
            if not line.strip():
                continue
            values = next(csv.reader([line]))
            padded = values + [""] * (len(_EXPECTED_COLUMNS) - len(values))
            row = dict(zip(_EXPECTED_COLUMNS, padded))

            ts = parse_iso(row["timestamp"])
            yield NormalizedLog(
                timestamp_utc=ts,
                source_format=SourceFormat.NETWORK_TRAFFIC,
                event_category=EventCategory.NETWORK_FLOW,
                source_file=str(path),
                raw=line,
                src_ip=_none_if_blank(row["src_ip"]),
                src_port=_int_or_none(row["src_port"]),
                dst_ip=_none_if_blank(row["dst_ip"]),
                dst_port=_int_or_none(row["dst_port"]),
                protocol=_none_if_blank(row["protocol"]),
                payload=_none_if_blank(row["payload"]),
                http_user_agent=_none_if_blank(row["http_user_agent"]),
                http_request=_none_if_blank(row["http_request"]),
            )
