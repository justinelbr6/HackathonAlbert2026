"""Tests for KEV, EPSS, cache and air-gap discipline (Étape 2.B)."""

from __future__ import annotations

import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.config import Settings  # noqa: E402
from marine_log_sentinel.threat_intel import kev as kev_mod  # noqa: E402
from marine_log_sentinel.threat_intel.epss import parse_epss_file  # noqa: E402
from marine_log_sentinel.threat_intel.kev import parse_kev_file  # noqa: E402


KEV_FIXTURE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "test",
    "dateReleased": "2026-05-12T00:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Log4Shell",
            "dateAdded": "2021-12-10",
            "shortDescription": "JNDI injection in Log4j",
            "requiredAction": "Patch",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
            "cwes": ["CWE-20"],
        },
        {
            "cveID": "CVE-2020-1472",
            "vendorProject": "Microsoft",
            "product": "Windows Netlogon",
            "vulnerabilityName": "Zerologon",
            "dateAdded": "2020-11-03",
            "shortDescription": "Privilege escalation in Netlogon",
            "requiredAction": "Patch",
            "dueDate": "2020-11-17",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
            "cwes": ["CWE-330"],
        },
    ],
}

EPSS_FIXTURE_TEXT = (
    "#model_version:v2026.01.01,score_date:2026-05-12T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2021-44228,0.974560000,0.999310000\n"
    "CVE-2020-1472,0.910120000,0.997020000\n"
    "CVE-1999-0001,0.000400000,0.094200000\n"
)


class KevParserTest(unittest.TestCase):
    def test_parses_official_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kev.json"
            path.write_text(json.dumps(KEV_FIXTURE), encoding="utf-8")
            entries = parse_kev_file(path)
        self.assertEqual(len(entries), 2)
        log4shell = entries["CVE-2021-44228"]
        self.assertEqual(log4shell.vendor, "Apache")
        self.assertEqual(log4shell.product, "Log4j2")
        self.assertEqual(log4shell.date_added.isoformat(), "2021-12-10")
        self.assertTrue(log4shell.known_ransomware)
        zerologon = entries["CVE-2020-1472"]
        self.assertFalse(zerologon.known_ransomware)


class EpssParserTest(unittest.TestCase):
    def test_parses_gzipped_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "epss.csv.gz"
            with gzip.open(path, "wb") as handle:
                handle.write(EPSS_FIXTURE_TEXT.encode("utf-8"))
            entries = parse_epss_file(path)
        self.assertEqual(len(entries), 3)
        log4shell = entries["CVE-2021-44228"]
        self.assertAlmostEqual(log4shell.score, 0.97456, places=5)
        self.assertGreater(log4shell.percentile, 0.99)

    def test_parses_plain_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "epss.csv"
            path.write_text(EPSS_FIXTURE_TEXT, encoding="utf-8")
            entries = parse_epss_file(path)
        self.assertIn("CVE-2020-1472", entries)


class CacheAirGapTest(unittest.TestCase):
    """Critical military-posture test: in air-gap mode, no fetch can happen."""

    def test_air_gap_blocks_network_fetch(self):
        from marine_log_sentinel.threat_intel import cache as cache_mod

        air_gapped_settings = Settings(air_gap_mode=True)
        with patch.object(cache_mod, "SETTINGS", air_gapped_settings):
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(cache_mod.AirGapError):
                    cache_mod.fetch(
                        "https://example.invalid/should-never-be-reached.bin",
                        name="bogus",
                        filename="payload.bin",
                        cache_dir=Path(tmp),
                    )

    def test_air_gap_offline_read_succeeds_when_cache_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache_dir = Path(tmp)
            kev_dir = cache_dir / "kev"
            kev_dir.mkdir(parents=True, exist_ok=True)
            payload_path = kev_dir / "known_exploited_vulnerabilities.json"
            payload_path.write_text(json.dumps(KEV_FIXTURE), encoding="utf-8")
            (kev_dir / "metadata.json").write_text(
                json.dumps(
                    {
                        "name": "kev",
                        "path": str(payload_path),
                        "sha256": "0" * 64,
                        "size_bytes": payload_path.stat().st_size,
                        "source_url": "https://example/kev.json",
                        "fetched_at_utc": "2026-05-12T00:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )
            entries, entry = kev_mod.load_kev_offline(cache_dir=cache_dir)
            self.assertEqual(len(entries), 2)
            self.assertEqual(entry.name, "kev")

    def test_offline_read_raises_when_cache_missing(self):
        from marine_log_sentinel.threat_intel.cache import CacheMissError

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(CacheMissError):
                kev_mod.load_kev_offline(cache_dir=Path(tmp))


class FetchHttpsOnlyTest(unittest.TestCase):
    def test_refuses_non_https(self):
        from marine_log_sentinel.threat_intel.cache import fetch

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                fetch(
                    "http://example.com/insecure",
                    name="x",
                    filename="y.bin",
                    cache_dir=Path(tmp),
                )


if __name__ == "__main__":
    unittest.main()
