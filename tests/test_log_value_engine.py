from pathlib import Path
import json
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from log_value_engine import (  # noqa: E402
    build_policy,
    export_policy,
    load_asset_inventory,
    load_mapping_rows,
    load_mitre_attack_techniques,
    recommend_similar_mitre_techniques,
    score_candidate,
)

DATA_DIR = PROJECT_ROOT / "SujetsHackathon2026" / "Sujet1" / "MiseEnJambe"
GENERALISATION_DIR = PROJECT_ROOT / "SujetsHackathon2026" / "Sujet1" / "Généralisation"
MAPPING_FILE = DATA_DIR / "mapping_ttps_cve_logs.csv"
MITRE_ZIP_FILE = GENERALISATION_DIR / "enterprise-attack.json.zip"
ASSET_FILE = PROJECT_ROOT / "ProjetsEtudiantsHackathon2026" / "asset_inventory_sample.csv"


class LogValueEngineTest(unittest.TestCase):
    def test_load_asset_inventory_exposes_context_for_scoring(self):
        assets = load_asset_inventory(ASSET_FILE)

        self.assertIn("web_frontend", assets)
        web_asset = assets["web_frontend"]
        self.assertEqual(web_asset["asset_type"], "web_server")
        self.assertEqual(web_asset["criticality"], "high")
        self.assertEqual(web_asset["exposure"], "internet")
        self.assertIn("Portail", web_asset["business_role"])

    def test_load_mapping_rows_normalizes_quoted_challenge_csv(self):
        rows = load_mapping_rows(MAPPING_FILE)

        self.assertEqual(len(rows), 5)
        first = rows[0]
        self.assertEqual(first["ttp_id"], "T1059")
        self.assertEqual(first["ttp_name"], "Command and Scripting Interpreter")
        self.assertEqual(first["log_source"], "Windows Sysmon")
        self.assertEqual(first["log_fields"], ["CommandLine", "ProcessName", "ParentProcessName"])

    def test_score_candidate_turns_context_into_explainable_priority(self):
        candidate = {
            "ttp_id": "T1059",
            "ttp_name": "Command and Scripting Interpreter",
            "ttp_tactic": "execution",
            "cve_score": "10",
            "log_type": "process",
            "log_source": "Windows Sysmon",
            "log_fields": ["CommandLine", "ProcessName", "ParentProcessName"],
        }

        scored = score_candidate(candidate, asset_type="windows_server", asset_criticality="high", strategy="balanced")

        self.assertEqual(scored["priority"], "indispensable")
        self.assertGreaterEqual(scored["log_value_score"], 8.0)
        self.assertEqual(scored["estimated_cost"], "moyen")
        self.assertEqual(scored["estimated_noise"], "moyen")
        self.assertIn("T1059", scored["reason"])
        self.assertIn("angle mort", scored["blind_spot_if_missing"].lower())

    def test_build_policy_filters_threat_and_returns_ranked_recommendations(self):
        policy = build_policy(
            MAPPING_FILE,
            threat_id="T1190",
            asset_id="web_frontend",
            asset_inventory_file=ASSET_FILE,
            strategy="balanced",
        )

        self.assertEqual(policy["policy"]["target"]["threat_id"], "T1190")
        self.assertEqual(policy["policy"]["target"]["asset_id"], "web_frontend")
        self.assertEqual(policy["policy"]["target"]["asset_type"], "web_server")
        self.assertEqual(policy["policy"]["target"]["exposure"], "internet")
        self.assertIn("Portail", policy["policy"]["target"]["business_role"])
        self.assertGreaterEqual(len(policy["policy"]["recommendations"]), 1)

        rec = policy["policy"]["recommendations"][0]
        self.assertEqual(rec["log_source"], "Apache Access Logs")
        self.assertEqual(rec["priority"], "indispensable")
        self.assertEqual(rec["fields"], ["HttpRequest", "UserAgent", "Payload"])
        self.assertIn("T1190", rec["covers"]["ttp_id"])
        self.assertIn("Log4j", rec["covers"]["cve_description"])

    def test_export_policy_writes_json_and_yaml_like_files(self):
        policy = build_policy(MAPPING_FILE, threat_id="T1048", asset_type="network", asset_criticality="medium")

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = export_policy(policy, Path(tmpdir), fmt="json")
            yaml_path = export_policy(policy, Path(tmpdir), fmt="yaml")

            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["policy"]["target"]["threat_id"], "T1048")
            self.assertIn("policy:", yaml_path.read_text(encoding="utf-8"))
            self.assertIn("T1048", yaml_path.read_text(encoding="utf-8"))

    def test_load_mitre_attack_techniques_uses_generalisation_dataset(self):
        techniques = load_mitre_attack_techniques(MITRE_ZIP_FILE)

        self.assertGreaterEqual(len(techniques), 600)
        by_id = {technique["ttp_id"]: technique for technique in techniques}
        self.assertIn("T1059", by_id)
        self.assertEqual(by_id["T1059"]["name"], "Command and Scripting Interpreter")
        self.assertIn("execution", by_id["T1059"]["tactics"])
        self.assertTrue(by_id["T1059"]["description"])

    def test_recommend_similar_mitre_techniques_generalizes_from_free_text(self):
        recommendations = recommend_similar_mitre_techniques(
            "PowerShell command execution and suspicious parent process on Windows server",
            mitre_zip_file=MITRE_ZIP_FILE,
            top_n=5,
        )

        self.assertEqual(len(recommendations), 5)
        self.assertEqual(recommendations[0]["ttp_id"], "T1059")
        self.assertGreater(recommendations[0]["similarity_score"], 0)
        self.assertIn("Command", recommendations[0]["why"])
        self.assertIn("Windows", recommendations[0]["matched_terms"])


if __name__ == "__main__":
    unittest.main()
