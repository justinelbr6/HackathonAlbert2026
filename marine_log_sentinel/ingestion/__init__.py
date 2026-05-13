"""Ingestion layer (Étape 1): parsers + normalization to a unified log schema."""

from marine_log_sentinel.ingestion.normalizer import (
    IngestResult,
    PARSERS,
    detect_format,
    file_sha256,
    normalize_directory,
    normalize_file,
)
from marine_log_sentinel.ingestion.parsers.base import ParserError
from marine_log_sentinel.ingestion.schema import (
    EventCategory,
    NormalizedLog,
    SourceFormat,
)

__all__ = [
    "EventCategory",
    "IngestResult",
    "NormalizedLog",
    "PARSERS",
    "ParserError",
    "SourceFormat",
    "detect_format",
    "file_sha256",
    "normalize_directory",
    "normalize_file",
]
