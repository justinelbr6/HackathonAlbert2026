"""Parser for Microsoft Sysmon JSON events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from marine_log_sentinel.ingestion.parsers._utils import parse_iso
from marine_log_sentinel.ingestion.parsers.base import BaseParser, ParserError
from marine_log_sentinel.ingestion.schema import EventCategory, NormalizedLog, SourceFormat


class SysmonParser(BaseParser):
    name = "sysmon"

    def parse(self, path: Path) -> Iterator[NormalizedLog]:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return

        records: list[tuple[str, dict]] = []
        try:
            records.append((text, json.loads(text)))
        except json.JSONDecodeError:
            for raw in text.splitlines():
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    records.append((stripped, json.loads(stripped)))
                except json.JSONDecodeError as exc:
                    raise ParserError(f"{path}: invalid Sysmon JSON") from exc

        for raw, obj in records:
            ts = parse_iso(str(obj.get("Timestamp", "")))
            event_id = obj.get("EventID")
            yield NormalizedLog(
                timestamp_utc=ts,
                source_format=SourceFormat.WINDOWS_SYSMON,
                event_category=EventCategory.PROCESS_EXECUTION,
                source_file=str(path),
                raw=raw,
                host=obj.get("Computer"),
                event_id=str(event_id) if event_id is not None else None,
                process_name=obj.get("ProcessName"),
                process_cmdline=obj.get("CommandLine"),
                parent_process_name=obj.get("ParentProcessName"),
            )
