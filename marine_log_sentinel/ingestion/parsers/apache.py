"""Parser for Apache combined access log format.

Despite the file being named `Apache.JSON` in the challenge dataset, the
content is a single-line Apache access log, not a JSON document.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterator

from marine_log_sentinel.ingestion.parsers.base import BaseParser, ParserError
from marine_log_sentinel.ingestion.schema import EventCategory, NormalizedLog, SourceFormat

_APACHE_RE = re.compile(
    r"^(?P<src_ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<ts>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>HTTP/\d\.\d)"\s+'
    r"(?P<status>\d+)\s+(?P<size>\d+|-)"
)


class ApacheParser(BaseParser):
    name = "apache"

    def parse(self, path: Path) -> Iterator[NormalizedLog]:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            match = _APACHE_RE.match(line)
            if not match:
                raise ParserError(f"{path}:{line_no} not a valid Apache access line")
            parts = match.groupdict()
            try:
                ts = datetime.strptime(parts["ts"], "%d/%b/%Y:%H:%M:%S %z")
            except ValueError as exc:
                raise ParserError(f"{path}:{line_no} bad timestamp: {parts['ts']}") from exc
            user = None if parts["user"] in {"-", ""} else parts["user"]
            yield NormalizedLog(
                timestamp_utc=ts,
                source_format=SourceFormat.APACHE_ACCESS,
                event_category=EventCategory.WEB_REQUEST,
                source_file=str(path),
                raw=line,
                src_ip=parts["src_ip"],
                user=user,
                http_method=parts["method"],
                http_path=parts["path"],
                http_status=int(parts["status"]),
                payload=parts["path"],
            )
