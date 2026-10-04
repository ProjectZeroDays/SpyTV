"""Unit tests for the detection layer (ssh / adb / ssdp detectors)."""
import unittest

from defense.detection.adb_detector import RogueAdbDetector
from defense.detection.events import Event
from defense.detection.ssh_detector import SshBruteForceDetector, parse_sshd_line
from defense.detection.ssdp_detector import SsdpAnomalyDetector

FAILED_LINE = ("Sep 30 21:04:11 tv sshd[123]: Failed password for invalid user admin "
               "from 203.0.113.9 port 41234 ssh2")
INVALID_LINE = "Sep 30 21:04:12 tv sshd[124]: Invalid user oracle from 203.0.113.9 port 41235 ssh2"
CLOSED_LINE = ("Sep 30 21:04:13 tv sshd[125]: Connection closed by authenticating user root "
               "203.0.113.9 port 41236 [preauth]")
ACCEPTED_LINE = "Sep 30 21:04:14 tv sshd[126]: Accepted publickey for dean from 192.0.2.10 port 51000 ssh2"


class TestParseSshdLine(unittest.TestCase):
    def test_failed_password(self):
        event = parse_sshd_line(FAILED_LINE, ts=1000.0)
        self.assertIsNotNone(event)
        self.assertEqual(event.kind, "ssh_auth_failure")
        self.assertEqual(event.src, "203.0.113.9")
        self.assertEqual(event.detail["user"], "admin")

    def test_invalid_user(self):
        event = parse_sshd_line(INVALID_LINE, ts=1000.0)
        self.assertIsNotNone(event)
        self.assertEqual(event.detail["user"], "oracle")

    def test_connection_closed_authenticating(self):
        event = parse_sshd_line(CLOSED_LINE, ts=1000.0)
        self.assertIsNotNone(event)
        self.assertEqual(event.detail["user"], "root")

    def test_accepted_is_ignored(self):
        self.assertIsNone(parse_sshd_line(ACCEPTED_LINE))


class TestSshBruteForce(unittest.TestCase):
    def _feed(self, detector, count, t0=0.0, step=1.0, line=FAILED_LINE):
        alerts = []
        for i in range(count):
            event = parse_sshd_line(line, ts=t0 + i * step)
            alerts.extend(detector.observe(event))
        return alerts

    def test_alert_at_threshold(self):
        det = SshBruteForceDetector(threshold=5, window=60, cooldown=300)
        self.assertEqual(len(self._feed(det, 4)), 0, "below threshold must not alert")
        alerts = self._feed(det, 1, t0=4.0)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        self.assertEqual(alerts[0].evidence["count"], 5)

    def test_cooldown_suppresses_repeats(self):
        det = SshBruteForceDetector(threshold=5, window=60, cooldown=300)
        self._feed(det, 5)                       # first alert
        more = self._feed(det, 5, t0=10.0)       # same attack, within cooldown
        self.assertEqual(len(more), 0)

    def test_window_expires(self):
        det = SshBruteForceDetector(threshold=5, window=60, cooldown=1)
        self._feed(det, 5)                        # alert (bucket now 5)
        late = self._feed(det, 1, t0=1000.0)      # window empty, count 1
        self.assertEqual(len(late), 0)

    def test_multiple_sources_tracked_separately(self):
        det = SshBruteForceDetector(threshold=2, window=60, cooldown=300)
        ev1 = parse_sshd_line(FAILED_LINE, ts=1.0)            # 203.0.113.9
        ev2 = parse_sshd_line(INVALID_LINE.replace("203.0.113.9", "198.51.100.7"), ts=2.0)
        det.observe(ev1)
        self.assertEqual(len(det.observe(ev2)), 0, "second source has only one hit")


class TestRogueAdb(unittest.TestCase):
    def _tcp(self, src, dst, dport, state="ESTABLISHED"):
        return Event(ts=1.0, kind="tcp", src=src, dst=dst, dport=dport,
                     detail={"state": state})

    def test_unknown_peer_alerts_once(self):
        det = RogueAdbDetector()
        alerts = det.observe(self._tcp("192.168.1.10", "192.168.1.50", 5555))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")
        dup = det.observe(self._tcp("192.168.1.10", "192.168.1.50", 5555))
        self.assertEqual(len(dup), 0, "same connection must not re-alert")

    def test_allowlisted_peer_ignored(self):
        det = RogueAdbDetector(allowed_peers={"192.168.1.50"})
        self.assertEqual(len(det.observe(self._tcp("192.168.1.10", "192.168.1.50", 5555))), 0)

    def test_other_ports_ignored(self):
        det = RogueAdbDetector()
        self.assertEqual(len(det.observe(self._tcp("192.168.1.10", "192.168.1.50", 443))), 0)

    def test_non_established_ignored(self):
        det = RogueAdbDetector()
        self.assertEqual(len(det.observe(self._tcp("192.168.1.10", "192.168.1.50", 5555, state="TIME_WAIT"))), 0)

    def test_adb_connect_process(self):
        det = RogueAdbDetector()
        alerts = det.observe(Event(ts=2.0, kind="process", detail={
            "name": "adb.exe", "cmdline": "adb connect 192.168.1.50:5555", "pid": 42}))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_adb_device_attach(self):
        det = RogueAdbDetector()
        alerts = det.observe(Event(ts=3.0, kind="adb_device",
                                   detail={"serial": "192.168.1.50:5555", "status": "unauthorized"}))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "MEDIUM")


class TestSsdpAnomaly(unittest.TestCase):
    def _burst(self, det, count, t0=0.0, method="M-SEARCH", vary_dst=False):
        alerts = []
        for i in range(count):
            dst = f"239.255.255.{(i % 250) + 1}" if vary_dst else "239.255.255.250"
            alerts.extend(det.observe(Event(
                ts=t0 + i * 0.1, kind="ssdp", src="10.0.0.9",
                dst=dst,
                detail={"method": method})))
        return alerts

    def test_burst_alerts(self):
        det = SsdpAnomalyDetector(rate_threshold=50, window=10)
        self.assertEqual(len(self._burst(det, 49)), 0)
        alerts = self._burst(det, 1, t0=4.9)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_normal_notify_cadence_no_alert(self):
        det = SsdpAnomalyDetector(rate_threshold=50, window=10)
        alerts = []
        for i in range(5):
            alerts.extend(det.observe(Event(ts=float(i) * 30, kind="ssdp", src="10.0.0.4",
                                            dst="239.255.255.250", detail={"method": "NOTIFY"})))
        self.assertEqual(len(alerts), 0)

    def test_fanout_by_distinct_dst(self):
        det = SsdpAnomalyDetector(rate_threshold=500, window=10, distinct_dst_threshold=25)
        alerts = self._burst(det, 25, vary_dst=True)   # 25 distinct dsts at 0.1s steps
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_cooldown(self):
        det = SsdpAnomalyDetector(rate_threshold=10, window=10, cooldown=120)
        self.assertEqual(len(self._burst(det, 12)), 1)
        self.assertEqual(len(self._burst(det, 12, t0=20.0)), 0)


if __name__ == "__main__":
    unittest.main()
