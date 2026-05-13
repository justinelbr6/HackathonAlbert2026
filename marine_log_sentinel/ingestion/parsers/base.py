"""Abstract base class for log parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable

from marine_log_sentinel.ingestion.schema import NormalizedLog


class ParserError(Exception):
    """Raised when a parser cannot extract a valid record from input."""


class BaseParser(ABC):
    name: str = "abstract"

    @abstractmethod
    def parse(self, path: Path) -> Iterable[NormalizedLog]:
        """Yield `NormalizedLog` records extracted from `path`."""
