"""Tests for hardening helpers: firmware audit findings and VLAN rule rendering."""
import unittest
from datetime import date

from defense.hardening.firmware_audit import audit_devices
from defense.hardening.vlan_segmentation import DEFAULT_POLICY, render_iptables, render_nftables

TODAY = date(2026, 10, 3)


class TestFirmwareAudit(unittest.TestCase):
    def test_healthy_device_no_findings(self):
        devices = [{"name": "A", "vendor": "samsung", "model": "X", "firmware": "1.2",
                    "auto_update": True, "last_checked": "2026-09-15"}]
        self.assertEqual(audit_devices(devices, today=TODAY), [])

    def test_auto_update_disabled_flagged_high(self):
        devices = [{"name": "B", "vendor": "amazon", "model": "Y", "firmware": "2.0",
                    "auto_update": False, "last_checked": "2026-09-20"}]
        findings = audit_devices(devices, today=TODAY)
        auto = [f for f in findings if f["check"] == "auto_update"]
        self.assertEqual(len(auto), 1)
        self.assertEqual(auto[0]["severity"], "HIGH")

    def test_stale_checkin_flagged_medium(self):
        devices = [{"name": "C", "vendor": "roku", "model": "Z", "firmware": "3",
                    "auto_update": True, "last_checked": "2026-01-01"}]
        findings = audit_devices(devices, today=TODAY)
        stale = [f for f in findings if f["check"] == "last_checked"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["severity"], "MEDIUM")

    def test_incomplete_inventory_flagged(self):
        findings = audit_devices([{"name": "D"}], today=TODAY)
        self.assertTrue(any(f["check"] == "inventory" for f in findings))
        self.assertTrue(any(f["check"] == "firmware" for f in findings))

    def test_unknown_vendor_low(self):
        devices = [{"name": "E", "vendor": "acme", "model": "M", "firmware": "9",
                    "auto_update": True, "last_checked": "2026-09-30"}]
        findings = audit_devices(devices, today=TODAY)
        self.assertTrue(any(f["check"] == "vendor" and f["severity"] == "LOW" for f in findings))


class TestVlanRendering(unittest.TestCase):
    def test_nftables_ruleset(self):
        text = render_nftables(DEFAULT_POLICY)
        self.assertIn("table inet iot_isolation", text)
        self.assertIn(DEFAULT_POLICY["iot_subnet"], text)
        self.assertIn(DEFAULT_POLICY["trusted_subnet"], text)
        self.assertIn("iot-to-lan-deny", text)
        self.assertIn("udp dport 53 accept", text)

    def test_nftables_rfc1918_block_optional(self):
        without = render_nftables(DEFAULT_POLICY)
        policy = dict(DEFAULT_POLICY)
        policy["block_iot_to_rfc1918"] = True
        with_block = render_nftables(policy)
        self.assertNotIn("10.0.0.0/8, 172.16.0.0/12", without)
        self.assertIn("10.0.0.0/8, 172.16.0.0/12", with_block)

    def test_iptables_ruleset(self):
        text = render_iptables(DEFAULT_POLICY)
        self.assertIn("IOT_ISOLATION", text)
        self.assertIn(f"-d {DEFAULT_POLICY['trusted_subnet']} -j DROP", text)
        self.assertIn("--dport 53 -j ACCEPT", text)


if __name__ == "__main__":
    unittest.main()
