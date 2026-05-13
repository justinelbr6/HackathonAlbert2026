"""Tests for Étape 1 — ingestion & normalization of the 6 challenge formats."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ingestion import (  # noqa: E402
    EventCategory,
    NormalizedLog,
    SourceFormat,
    detect_format,
    normalize_file,
)

CHALLENGE_DIR = PROJECT_ROOT / "SujetsHackathon2026" / "Sujet1" / "MiseEnJambe"


class FormatDetectionTest(unittest.TestCase):
    def test_detect_each_known_format(self):
        cases = [
            ("Apache.JSON", "apache"),
            ("Suricata.JSON", "suricata"),
            ("Sysmon.JSON", "sysmon"),
            ("sample_logs_windows_events.csv", "windows_events"),
            ("sample_logs_linux_syslog.CSV.log", "linux_syslog"),
            ("sample_logs_network_traffic.csv.xlsx", "network_traffic"),
        ]
        for filename, expected in cases:
            with self.subTest(file=filename):
                self.assertEqual(detect_format(CHALLENGE_DIR / filename), expected)


class ApacheParserTest(unittest.TestCase):
    def test_parses_log4shell_attempt(self):
        result = normalize_file(CHALLENGE_DIR / "Apache.JSON")

        self.assertEqual(result.detected_format, "apache")
        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertIsInstance(record, NormalizedLog)
        self.assertEqual(record.source_format, SourceFormat.APACHE_ACCESS)
        self.assertEqual(record.event_category, EventCategory.WEB_REQUEST)
        self.assertEqual(record.src_ip, "192.168.1.100")
        self.assertEqual(record.http_method, "GET")
        self.assertIn("${jndi:", record.http_path)
        self.assertEqual(record.http_status, 200)


class SuricataParserTest(unittest.TestCase):
    def test_parses_alert_with_signature_and_severity(self):
        result = normalize_file(CHALLENGE_DIR / "Suricata.JSON")

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.source_format, SourceFormat.SURICATA_EVE)
        self.assertEqual(record.event_category, EventCategory.NETWORK_ALERT)
        self.assertEqual(record.src_ip, "192.168.1.100")
        self.assertEqual(record.dst_ip, "10.0.0.5")
        self.assertEqual(record.signature, "ET TROJAN Possible Log4j RCE Attempt")
        self.assertEqual(record.signature_severity, "high")


class SysmonParserTest(unittest.TestCase):
    def test_parses_process_create_event(self):
        result = normalize_file(CHALLENGE_DIR / "Sysmon.JSON")

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.source_format, SourceFormat.WINDOWS_SYSMON)
        self.assertEqual(record.event_category, EventCategory.PROCESS_EXECUTION)
        self.assertEqual(record.host, "WIN-SRV-01")
        self.assertEqual(record.event_id, "1")
        self.assertEqual(record.process_name, "powershell.exe")
        self.assertEqual(record.parent_process_name, "explorer.exe")
        self.assertIn("DownloadString", record.process_cmdline)


class WindowsEventsParserTest(unittest.TestCase):
    def test_parses_quoted_csv_with_powershell_payload(self):
        result = normalize_file(CHALLENGE_DIR / "sample_logs_windows_events.csv")

        self.assertGreaterEqual(len(result.records), 5)
        powershell = [r for r in result.records if r.process_name == "powershell.exe"]
        self.assertGreaterEqual(len(powershell), 1)
        self.assertIn("DownloadString", powershell[0].process_cmdline)

    def test_categorizes_events_by_source(self):
        result = normalize_file(CHALLENGE_DIR / "sample_logs_windows_events.csv")

        categories = {r.event_category for r in result.records}
        self.assertIn(EventCategory.PROCESS_EXECUTION, categories)
        self.assertIn(EventCategory.SCHEDULED_TASK, categories)
        self.assertIn(EventCategory.AUTHENTICATION, categories)


class LinuxSyslogParserTest(unittest.TestCase):
    def test_parses_ssh_cron_and_sudo_subformats(self):
        result = normalize_file(CHALLENGE_DIR / "sample_logs_linux_syslog.CSV.log")

        self.assertGreaterEqual(len(result.records), 7)
        kinds = {r.event_category for r in result.records}
        self.assertIn(EventCategory.AUTHENTICATION, kinds)
        self.assertIn(EventCategory.SCHEDULED_TASK, kinds)
        self.assertIn(EventCategory.PROCESS_EXECUTION, kinds)

    def test_sshd_authentication_extracts_source_ip(self):
        result = normalize_file(CHALLENGE_DIR / "sample_logs_linux_syslog.CSV.log")
        sshd = [r for r in result.records if r.process_name == "sshd"]

        self.assertTrue(any(r.src_ip == "192.168.1.100" for r in sshd))
        self.assertTrue(any(r.src_ip == "104.28.15.200" for r in sshd))


class NetworkTrafficParserTest(unittest.TestCase):
    def test_parses_xlsx_rows(self):
        result = normalize_file(CHALLENGE_DIR / "sample_logs_network_traffic.csv.xlsx")

        self.assertGreaterEqual(len(result.records), 6)
        first = result.records[0]
        self.assertEqual(first.source_format, SourceFormat.NETWORK_TRAFFIC)
        self.assertEqual(first.src_ip, "192.168.1.100")
        self.assertEqual(first.dst_ip, "104.28.15.200")
        self.assertEqual(first.protocol, "TCP")

    def test_log4shell_user_agent_is_preserved(self):
        result = normalize_file(CHALLENGE_DIR / "sample_logs_network_traffic.csv.xlsx")
        log4shell = [r for r in result.records if r.http_user_agent and "${jndi:" in r.http_user_agent]
        self.assertEqual(len(log4shell), 1)


class IngestResultMetadataTest(unittest.TestCase):
    def test_result_carries_sha256_and_format(self):
        result = normalize_file(CHALLENGE_DIR / "Apache.JSON")
        self.assertEqual(len(result.sha256), 64)
        self.assertEqual(result.detected_format, "apache")
        self.assertEqual(result.errors, [])


if __name__ == "__main__":
    unittest.main()
