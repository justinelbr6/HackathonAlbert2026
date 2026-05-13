"""Reporting layer (Étape 6): officer-facing standalone HTML report."""

from marine_log_sentinel.reporting.html_report import (
    build_officer_html_document,
    write_officer_html_report,
)

__all__ = [
    "build_officer_html_document",
    "write_officer_html_report",
]
