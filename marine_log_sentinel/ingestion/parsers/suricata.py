"""Parser for Suricata EVE JSON events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from marine_log_sentinel.ingestion.parsers._utils import parse_iso
from marine_log_sentinel.ingestion.parsers.base import BaseParser, ParserError
from marine_log_sentinel.ingestion.schema import EventCategory, NormalizedLog, SourceFormat


class SuricataParser(BaseParser):
    name = "suricata"

    def parse(self, path: Path) -> Iterator[NormalizedLog]:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return

        # The Suricata EVE format is conventionally NDJSON (one JSON object per
        # line) but the challenge ships a single multi-line object. Accept both.
        records: list[tuple[str, dict]] = []
        try:
            obj = json.loads(text)
            records.append((text, obj))
        except json.JSONDecodeError:
            for raw in text.splitlines():
                stripped = raw.strip()
                if not stripped:
                    continue
                try:
                    records.append((stripped, json.loads(stripped)))
                except json.JSONDecodeError as exc:
                    raise ParserError(f"{path}: invalid JSON record") from exc

        for raw, obj in records:
            ts = parse_iso(str(obj.get("timestamp", "")))
            event_type = obj.get("event_type", "")
            category = (
                EventCategory.NETWORK_ALERT
                if event_type == "alert"
                else EventCategory.NETWORK_FLOW
            )
            alert = obj.get("alert") or {}
            yield NormalizedLog(
                timestamp_utc=ts,
                source_format=SourceFormat.SURICATA_EVE,
                event_category=category,
                source_file=str(path),
                raw=raw,
                src_ip=obj.get("src_ip"),
                src_port=obj.get("src_port"),
                dst_ip=obj.get("dest_ip"),
                dst_port=obj.get("dest_port"),
                protocol=obj.get("proto"),
                signature=alert.get("signature"),
                signature_severity=alert.get("severity"),
            )
