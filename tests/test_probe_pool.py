"""Tests for the bounded TCP probe pool (``core.cve_scanner.probe_many``).

The pool's parallelism has to be spread across **hosts**, never across the
ports of a single host. It used to be spread across whatever the job list
happened to contain, and callers build that list host-major — so the first 64
jobs all belonged to the first four addresses, and one device received 64
simultaneous connections.

Measured on a device that accepts every connection (16 signature ports,
sequential reference 16/16):

    workers=64 -> 3/16     workers=8  -> 13/16
    workers=16 -> 8/16     workers=4  -> 16/16

The ports that survive decide which family ``detect_tv_type()`` picks, so the
same television was returned as "LG webOS" by the scan (only port 3000 was
seen) and "Samsung Tizen" by /api/check (which probes sequentially) — two
different CVE sets and two different exploit modules for one device.
"""
import threading
import time

import core.cve_scanner as cs


class _Recorder:
    """Stands in for probe_port and records how many probes are live per host."""

    def __init__(self, delay=0.01):
        self.delay = delay
        self.live = {}
        self.max_live = {}
        self.total_live = 0
        self.total_max = 0
        self.lock = threading.Lock()

    def probe(self, ip, port, timeout=0.3):
        with self.lock:
            self.live[ip] = self.live.get(ip, 0) + 1
            self.max_live[ip] = max(self.max_live.get(ip, 0), self.live[ip])
            self.total_live += 1
            self.total_max = max(self.total_max, self.total_live)
        time.sleep(self.delay)
        with self.lock:
            self.live[ip] -= 1
            self.total_live -= 1
        return port % 2 == 0


def test_probe_many_never_fans_out_onto_a_single_host(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(cs, "probe_port", rec.probe)

    hosts = [f"10.0.0.{i}" for i in range(1, 7)]
    jobs = [(ip, p) for ip in hosts for p in range(24)]   # host-major, as callers build it
    results = cs.probe_many(jobs, workers=64)

    assert len(results) == len(jobs)
    assert rec.max_live, "no probes ran"
    assert max(rec.max_live.values()) <= cs.PER_HOST_WORKERS, rec.max_live
    # The cap must not collapse the pool into a serial scan.
    assert rec.total_max >= 2, f"pool never ran more than one probe: {rec.total_max}"


def test_probe_many_spreads_the_pool_across_hosts(monkeypatch):
    """Port-major ordering: a host-major queue would feed the first `workers`
    jobs to four addresses and then park most of the pool on the per-host
    caps."""
    rec = _Recorder()
    monkeypatch.setattr(cs, "probe_port", rec.probe)

    hosts = [f"10.1.0.{i}" for i in range(1, 9)]
    jobs = [(ip, p) for ip in hosts for p in range(32)]   # 8 hosts x 32 ports
    cs.probe_many(jobs, workers=8, per_host=1)

    # With per_host=1 and 8 workers, all 8 addresses can be probed at once.
    assert rec.total_max == 8, rec.total_max
    assert all(v == 1 for v in rec.max_live.values()), rec.max_live


def test_probe_many_returns_results_in_job_order(monkeypatch):
    """Internal reordering must not shift the results: callers map them back
    by position (``probes[base + j]``)."""
    monkeypatch.setattr(cs, "probe_port",
                        lambda ip, port, timeout=0.3: port == 7)
    jobs = [(f"10.2.0.{i}", p) for i in range(1, 5) for p in range(1, 12)]
    results = cs.probe_many(jobs, workers=32)

    assert results == [p == 7 for _ip, p in jobs]


def test_probe_many_progress_is_monotonic_and_completes(monkeypatch):
    monkeypatch.setattr(cs, "probe_port",
                        lambda ip, port, timeout=0.3: True)
    jobs = [("10.3.0.1", p) for p in range(20)]
    seen = []
    results = cs.probe_many(jobs, on_progress=lambda d, t: seen.append((d, t)))

    assert results == [True] * 20
    assert seen, "no progress reported"
    assert seen[-1] == (20, 20), seen[-1]
    assert all(b[0] >= a[0] for a, b in zip(seen, seen[1:])), seen


def test_probe_many_empty_job_list():
    seen = []
    assert cs.probe_many([], on_progress=lambda d, t: seen.append((d, t))) == []
    assert seen == [(0, 0)], seen
