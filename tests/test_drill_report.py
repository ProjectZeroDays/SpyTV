"""Tests for the detection drill and the incident summary report."""
import json
import tempfile
import unittest
from pathlib import Path

from defense.detection.drill import SCENARIOS, run_drill
from defense.detection.report import build_summary, build_timeline, load_alerts


class TestDrill(unittest.TestCase):
    def test_all_scenarios_hit_expected_counts(self):
        failures, rows = run_drill()
        self.assertEqual(failures, 0)
        self.assertEqual(len(rows), len(SCENARIOS))
        for row in rows:
            self.assertEqual(row["fired"], row["expected"], msg=row["scenario"])

    def test_single_scenario_selection(self):
        failures, rows = run_drill(selected=["benign"])
        self.assertEqual(failures, 0)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scenario"], "benign")
        self.assertEqual(rows[0]["fired"], 0)

    def test_drill_writes_alert_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "drill.jsonl"
            run_drill(selected=["ssh_bruteforce", "adb_takeover"], alert_file=path)
            lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(lines), 5)  # 1 brute-force + 4 ADB alerts
            self.assertTrue(all("detector" in a for a in lines))


class TestReport(unittest.TestCase):
    ALERTS = [
        {"ts": 1000.0, "detector": "ssh_bruteforce", "severity": "HIGH",
         "title": "SSH brute force from 203.0.113.9", "evidence": {"src": "203.0.113.9"}},
        {"ts": 1001.5, "detector": "rogue_adb", "severity": "HIGH",
         "title": "Connection to ADB port 5555", "evidence": {"peer": "192.168.1.64"}},
        {"ts": 1002.0, "detector": "rogue_adb", "severity": "MEDIUM",
         "title": "ADB device attached", "evidence": {"serial": "192.168.1.64:5555"}},
    ]

    def test_summary_counts(self):
        text = build_summary(self.ALERTS)
        self.assertIn("Total alerts:** 3", text)
        self.assertIn("HIGH 2", text)
        self.assertIn("rogue_adb 2", text)
        self.assertIn("203.0.113.9", text)

    def test_timeline_rows_and_cap(self):
        self.assertEqual(len(build_timeline(self.ALERTS).splitlines()), 5)  # header + sep + 3 rows
        many = [{"ts": float(i), "detector": "d", "severity": "LOW", "title": f"t{i}", "evidence": {}}
                for i in range(250)]
        self.assertIn("more alert(s) not shown", build_timeline(many, cap=200))

    def test_empty_summary(self):
        self.assertIn("No alerts found", build_summary([]))

    def test_load_alerts_skips_malformed_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            path.write_text('{"ts": 1}\nnot-json\n\n{"ts": 2}\n', encoding="utf-8")
            self.assertEqual(len(load_alerts(path)), 2)
            self.assertEqual(load_alerts(Path(tmp) / "missing.jsonl"), [])


if __name__ == "__main__":
    unittest.main()
