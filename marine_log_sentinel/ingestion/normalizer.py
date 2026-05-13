"""Format auto-detection and orchestration of per-format parsers.

Single public entry point: `normalize_file(path)`. The file is hashed
(SHA-256), the right parser is dispatched, and the result is recorded in
the tamper-evident audit log together with the file digest and the number
of OK / failed records. This produces a forensically defensible trail
linking every normalized record back to its source artefact.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from marine_log_sentinel.ingestion.parsers.apache import ApacheParser
from marine_log_sentinel.ingestion.parsers.base import BaseParser, ParserError
from marine_log_sentinel.ingestion.parsers.linux_syslog import LinuxSyslogParser
from marine_log_sentinel.ingestion.parsers.network_traffic import NetworkTrafficParser
from marine_log_sentinel.ingestion.parsers.suricata import SuricataParser
from marine_log_sentinel.ingestion.parsers.sysmon import SysmonParser
from marine_log_sentinel.ingestion.parsers.windows_events import WindowsEventsParser
from marine_log_sentinel.ingestion.schema import NormalizedLog
from marine_log_sentinel.observability.audit import record as audit_record
from marine_log_sentinel.observability.logger import get_logger

LOGGER = get_logger(__name__)


PARSERS: dict[str, BaseParser] = {
    "apache": ApacheParser(),
    "suricata": SuricataParser(),
    "sysmon": SysmonParser(),
    "windows_events": WindowsEventsParser(),
    "linux_syslog": LinuxSyslogParser(),
    "network_traffic": NetworkTrafficParser(),
}


def detect_format(path: Path) -> str:
    """Identify which parser should handle `path` based on its filename."""

    name = path.name.lower()
    if "apache" in name:
        return "apache"
    if "suricata" in name:
        return "suricata"
    if "sysmon" in name and "events" not in name:
        return "sysmon"
    if "windows_events" in name:
        return "windows_events"
    if "syslog" in name:
        return "linux_syslog"
    if "network_traffic" in name or name.endswith(".xlsx"):
        return "network_traffic"
    raise ParserError(f"Unable to auto-detect format for {path.name}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class IngestResult:
    """Outcome of normalizing a single source file."""

    source_file: Path
    detected_format: str
    sha256: str
    records: list[NormalizedLog] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def normalize_file(path: Path, *, format_hint: str | None = None) -> IngestResult:
    """Normalize one file. The SHA-256 and counts are written to the audit log."""

    path = Path(path)
    detected = format_hint or detect_format(path)
    parser = PARSERS.get(detected)
    if parser is None:
        raise ParserError(f"No parser registered for format {detected}")

    sha = file_sha256(path)
    result = IngestResult(source_file=path, detected_format=detected, sha256=sha)
    try:
        for record in parser.parse(path):
            result.records.append(record)
    except ParserError as exc:
        result.errors.append(str(exc))
        LOGGER.error(
            "ingest.parser_error",
            extra={"file": str(path), "format": detected, "error": str(exc)},
        )

    audit_record(
        "ingest.file",
        payload={
            "file": str(path),
            "sha256": sha,
            "format": detected,
            "records_ok": len(result.records),
            "errors": len(result.errors),
        },
    )
    return result


def normalize_directory(directory: Path, *, glob: str = "*") -> Iterator[IngestResult]:
    """Normalize every recognizable file under `directory`."""

    for path in sorted(Path(directory).glob(glob)):
        if not path.is_file():
            continue
        try:
            detect_format(path)
        except ParserError as exc:
            LOGGER.info("ingest.skip", extra={"file": str(path), "reason": str(exc)})
            continue
        yield normalize_file(path)
