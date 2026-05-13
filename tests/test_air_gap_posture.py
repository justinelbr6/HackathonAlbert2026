"""Étape 7 — consolidated air-gap posture checks beyond cache.fetch."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from marine_log_sentinel.config import Settings  # noqa: E402
from marine_log_sentinel.threat_intel.snapshot import (  # noqa: E402
    DEFAULT_MITRE_ZIP,
    sync_threat_intel,
)


class SyncThreatIntelAirGapTest(unittest.TestCase):
    def test_sync_threat_intel_refuses_when_air_gap_on(self):
        import marine_log_sentinel.threat_intel.snapshot as snap_mod

        isolated = Settings(air_gap_mode=True)
        with patch.object(snap_mod, "SETTINGS", isolated):
            with self.assertRaises(RuntimeError) as ctx:
                sync_threat_intel()
            self.assertIn("air-gap", str(ctx.exception).lower())


@unittest.skipUnless(DEFAULT_MITRE_ZIP.exists(), "MITRE bundle path absent from workspace")
class LoadThreatIntelOfflineWhileAirGapTest(unittest.TestCase):
    """``load_threat_intel`` must remain strictly offline (no HTTP)."""

    def test_snapshot_loads_with_air_gap_flag_true(self):
        import marine_log_sentinel.threat_intel.snapshot as snap_mod
        from marine_log_sentinel.threat_intel import load_threat_intel

        isolated = Settings(air_gap_mode=True)
        with patch.object(snap_mod, "SETTINGS", isolated):
            snap = load_threat_intel()
            self.assertGreaterEqual(len(snap.techniques), 100)


if __name__ == "__main__":
    unittest.main()
