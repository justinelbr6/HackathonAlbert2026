"""Parser for the Linux syslog text format.

Recognises the three sub-formats present in the challenge sample:
  - sshd authentication events (Accepted / Failed password ...)
  - CRON jobs (... CRON[pid]: (user) CMD (...))
  - sudo invocations (... sudo: user : TTY=...; PWD=...; USER=...; COMMAND=...)

Each sub-format yields a fully populated `NormalizedLog`. Other syslog
lines still produce a record with `event_category = OTHER` so that the
ML layer can still surface anomalies on them later.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from marine_log_sentinel.ingestion.parsers.base import BaseParser, ParserError
from marine_log_sentinel.ingestion.schema import EventCategory, NormalizedLog, SourceFormat

_SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d{1,2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>\w+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_SSHD_OK = re.compile(
    r"^Accepted password for(?: user)? (?P<user>\S+) from (?P<src>\S+) port (?P<port>\d+) ssh2"
)
_SSHD_FAIL = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+) port (?P<port>\d+) ssh2"
)
_CRON_CMD = re.compile(r"^\((?P<user>\S+)\) CMD \((?P<cmd>.*)\)$")
_SUDO_CMD = re.compile(
    r"^\s*(?P<actor>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<user>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$"
)


def _parse_syslog_timestamp(value: str, *, year_fallback: int) -> datetime:
    cleaned = re.sub(r"\s+", " ", value.strip())
    naive = datetime.strptime(f"{cleaned} {year_fallback}", "%b %d %H:%M:%S %Y")
    return naive.replace(tzinfo=timezone.utc)


class LinuxSyslogParser(BaseParser):
    name = "linux_syslog"

    def __init__(self, year_fallback: int | None = None) -> None:
        self._year_fallback = year_fallback or datetime.now(timezone.utc).year

    def parse(self, path: Path) -> Iterator[NormalizedLog]:
        text = path.read_text(encoding="utf-8", errors="replace")
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.rstrip("\r\n")
            if not line.strip():
                continue
            normalized_line = line
            if line.startswith('"') and line.endswith('"'):
                normalized_line = line[1:-1].replace('""', '"')

            match = _SYSLOG_RE.match(normalized_line)
            if not match:
                raise ParserError(f"{path}:{line_no} not a valid syslog line")

            ts = _parse_syslog_timestamp(match.group("ts"), year_fallback=self._year_fallback)
            host = match.group("host")
            proc = match.group("proc")
            msg = match.group("msg")

            category = EventCategory.OTHER
            user: str | None = None
            src_ip: str | None = None
            src_port: int | None = None
            process_cmdline: str | None = None

            if proc == "sshd":
                category = EventCategory.AUTHENTICATION
                sub = _SSHD_OK.match(msg) or _SSHD_FAIL.match(msg)
                if sub is not None:
                    user = sub.group("user")
                    src_ip = sub.group("src")
                    src_port = int(sub.group("port"))
            elif proc == "CRON":
                category = EventCategory.SCHEDULED_TASK
                sub = _CRON_CMD.match(msg)
                if sub is not None:
                    user = sub.group("user")
                    process_cmdline = sub.group("cmd")
            elif proc == "sudo":
                category = EventCategory.PROCESS_EXECUTION
                sub = _SUDO_CMD.match(msg)
                if sub is not None:
                    user = sub.group("user")
                    process_cmdline = sub.group("cmd")

            yield NormalizedLog(
                timestamp_utc=ts,
                source_format=SourceFormat.LINUX_SYSLOG,
                event_category=category,
                source_file=str(path),
                raw=line,
                host=host,
                user=user,
                process_name=proc,
                process_cmdline=process_cmdline,
                src_ip=src_ip,
                src_port=src_port,
                message=msg,
            )
