"""Tests for the observability layer of Marine Log Sentinel.

Written in plain `unittest` style so the audit chain can be validated even
before optional dev dependencies (pytest) are installed.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.observability.audit import record, verify_chain  # noqa: E402


class AuditChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.audit_path = Path(self._tmp.name) / "audit.jsonl"

    def test_audit_chain_is_valid_after_multiple_entries(self):
        record("first.action", payload={"foo": 1}, audit_log_path=self.audit_path)
        record("second.action", payload={"bar": 2}, audit_log_path=self.audit_path)
        record("third.action", payload={"baz": 3}, audit_log_path=self.audit_path)

        valid, count, broken = verify_chain(self.audit_path)

        self.assertTrue(valid)
        self.assertEqual(count, 3)
        self.assertIsNone(broken)

    def test_audit_chain_detects_payload_tampering(self):
        record("first.action", payload={"foo": 1}, audit_log_path=self.audit_path)
        record("second.action", payload={"bar": 2}, audit_log_path=self.audit_path)

        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["payload_digest"] = "0" * 64
        lines[0] = json.dumps(tampered, ensure_ascii=False)
        self.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, _count, broken = verify_chain(self.audit_path)

        self.assertFalse(valid)
        self.assertIsNotNone(broken)

    def test_audit_chain_detects_reorder_tampering(self):
        record("first.action", payload={"foo": 1}, audit_log_path=self.audit_path)
        record("second.action", payload={"bar": 2}, audit_log_path=self.audit_path)
        record("third.action", payload={"baz": 3}, audit_log_path=self.audit_path)

        lines = self.audit_path.read_text(encoding="utf-8").splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        self.audit_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        valid, _count, broken = verify_chain(self.audit_path)

        self.assertFalse(valid)
        self.assertIsNotNone(broken)

    def test_audit_chain_empty_log_is_valid(self):
        missing = self.audit_path.parent / "nonexistent.jsonl"

        valid, count, broken = verify_chain(missing)

        self.assertTrue(valid)
        self.assertEqual(count, 0)
        self.assertIsNone(broken)

    def test_record_returns_entry_with_chained_prev_hash(self):
        first = record("first.action", payload={"foo": 1}, audit_log_path=self.audit_path)
        second = record("second.action", payload={"bar": 2}, audit_log_path=self.audit_path)

        self.assertEqual(first.prev_hash, "0" * 64)
        self.assertEqual(second.prev_hash, first.this_hash)
        self.assertNotEqual(first.this_hash, second.this_hash)


if __name__ == "__main__":
    unittest.main()
