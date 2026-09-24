import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from radar.core import analyze, validate_thresholds
from radar.sources import reject_secrets


ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 9, 24, tzinfo=timezone.utc)


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "examples" / "demo.json").read_text(encoding="utf-8"))

    def test_nested_and_direct_privileges(self):
        report = analyze(self.data, now=NOW)
        alice = next(a for a in report["accounts"] if a["name"] == "alice")
        service = next(a for a in report["accounts"] if a["name"] == "svc-backup")
        self.assertEqual(alice["nested_groups"], ["Domain Admins"])
        self.assertEqual(service["direct_groups"], ["Backup Operators", "Domain Admins"])
        self.assertTrue(any(f["rule"] == "NESTED_PRIVILEGE" and f["object_name"] == "alice" for f in report["findings"]))
        self.assertTrue(any(f["rule"] == "SERVICE_INTERACTIVE" for f in report["findings"]))

    def test_unknown_interactive_login_is_not_a_finding(self):
        self.data["users"][1]["interactive_login_allowed"] = None
        report = analyze(self.data, now=NOW)
        self.assertFalse(any(f["rule"] == "SERVICE_INTERACTIVE" for f in report["findings"]))

    def test_thresholds_affect_findings(self):
        report = analyze(self.data, {"inactive_days": 2000, "service_inactive_days": 2000}, NOW)
        self.assertFalse(any(f["rule"] == "INACTIVE_ENABLED" for f in report["findings"]))
        with self.assertRaises(ValueError):
            validate_thresholds({"high_score": 90})

    def test_cycle_and_duplicates(self):
        self.data["groups"][2]["members"].append("CN=Domain Admins,DC=demo,DC=local")
        self.assertIsNotNone(analyze(self.data, now=NOW)["security_score"])
        self.data["users"].append(dict(self.data["users"][0]))
        with self.assertRaises(ValueError):
            analyze(self.data, now=NOW)

    def test_reject_password_fields(self):
        with self.assertRaises(ValueError):
            reject_secrets({"users": [{"password": "not stored"}]})


if __name__ == "__main__":
    unittest.main()
