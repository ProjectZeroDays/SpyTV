"""Tests for the CVE monitor: fetch injection, dedupe, alert formatting."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from defense.cve_monitor import monitor as cm

CANNED = {
    "totalResults": 2,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-12345",
                "published": "2026-09-30T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "RCE in ExampleTV webos stack"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.8}}]},
                "references": [
                    {"url": "https://www.exploit-db.com/exploits/99999"},
                    {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"},
                ],
            }
        },
        {
            "cve": {
                "id": "CVE-2026-67890",
                "published": "2026-09-29T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Info leak in vendor portal"}],
                "metrics": {},
                "references": [{"url": "https://example.com/advisory"}],
            }
        },
    ],
}


class FakeFetch:
    def __init__(self, payload=CANNED):
        self.payload = payload
        self.urls: list[str] = []

    def __call__(self, url, headers):
        self.urls.append(url)
        return self.payload


class TestSummarize(unittest.TestCase):
    def test_severity_and_exploit_flag(self):
        cve = CANNED["vulnerabilities"][0]["cve"]
        s = cm.summarize(cve)
        self.assertEqual(s["id"], "CVE-2026-12345")
        self.assertEqual(s["severity"], "HIGH")
        self.assertEqual(s["score"], 8.8)
        self.assertTrue(s["public_exploit_ref"])

    def test_no_metrics(self):
        cve = CANNED["vulnerabilities"][1]["cve"]
        s = cm.summarize(cve)
        self.assertIsNone(s["severity"])
        self.assertFalse(s["public_exploit_ref"])


class TestRunCycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.keywords = self.root / "keywords.json"
        self.keywords.write_text(json.dumps(["smart tv", "webos"]), encoding="utf-8")
        self.state = self.root / "state.json"
        self.alerts = self.root / "alerts.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def _cycle(self, fetch):
        return cm.run_cycle(
            keywords_file=self.keywords,
            days=7,
            state_file=self.state,
            alert_file=self.alerts,
            webhook=None,
            api_key=None,
            fetch_fn=fetch,
        )

    def test_first_cycle_alerts_and_dedupes(self):
        fetch = FakeFetch()
        new = self._cycle(fetch)
        self.assertEqual(new, 2)
        lines = [json.loads(x) for x in self.alerts.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(lines), 2)
        by_id = {x["id"]: x for x in lines}
        self.assertIn("smart tv", by_id["CVE-2026-12345"]["matched_keywords"])
        self.assertIn("webos", by_id["CVE-2026-12345"]["matched_keywords"])
        # Second cycle sees the same data: nothing new.
        self.assertEqual(self._cycle(FakeFetch()), 0)
        self.assertEqual(len(self.alerts.read_text(encoding="utf-8").splitlines()), 2)

    def test_query_urls_wellformed(self):
        fetch = FakeFetch()
        self._cycle(fetch)
        self.assertEqual(len(fetch.urls), 2)  # one per keyword
        for url in fetch.urls:
            self.assertIn(cm.NVD_BASE, url)
            self.assertIn("keywordSearch=", url)
            self.assertIn("pubStartDate=", url)
            self.assertIn("pubEndDate=", url)

    def test_format_alert_flags_public_exploit(self):
        s = cm.summarize(CANNED["vulnerabilities"][0]["cve"])
        s["matched_keywords"] = ["webos"]
        text = cm.format_alert(s)
        self.assertIn("CVE-2026-12345", text)
        self.assertIn("public exploit reference", text)

    def test_state_written(self):
        self._cycle(FakeFetch())
        state = json.loads(self.state.read_text(encoding="utf-8"))
        self.assertIn("CVE-2026-12345", state["seen"])
        self.assertIsNotNone(state["last_run"])


if __name__ == "__main__":
    unittest.main()
