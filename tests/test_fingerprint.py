"""Unit tests for core.fingerprint: scored matching, OUI, version filtering."""
import core.fingerprint as fp
from core.cve_scanner import TV_CVE_DATABASE, CVEScanner, _PORT_USAGE


def _detect(open_ports):
    return fp.best_family_match(open_ports, TV_CVE_DATABASE, _PORT_USAGE)


def test_shared_port_alone_never_classifies():
    """A single generic port must not claim a host — the live 10.1.10.0/24
    run caught the scanner host as 'Chromecast' off port 8443 this way."""
    assert _detect([22]) == (None, None)
    assert _detect([80]) == (None, None)
    assert _detect([80, 8443]) == (None, None)  # the original false positive
    assert _detect([49152]) == (None, None)


def test_distinctive_port_classifies_confidently():
    tv_type, info = _detect([8009])
    assert tv_type == "chromecast"
    tv_type, _ = _detect([8060])
    assert tv_type == "roku"
    tv_type, _ = _detect([5555])
    assert tv_type == "android-tv"


def test_real_world_lg_case_still_classifies():
    """The user's LG fleet presents 22/80/8080 (no 3000) — scored matching
    must keep finding it: 8080 is unique to lg-webos in the database."""
    tv_type, info = _detect([22, 80, 8080])
    assert tv_type == "lg-webos", tv_type
    assert info["name"] == "LG webOS TV"


def test_scored_match_beats_dict_order():
    """Both chromecast and android-tv see [8009, 5555]; the distinctive port
    (8009, unique) must outweigh the shared one (5555, in 3 families)."""
    tv_type, _ = _detect([8009, 5555])
    assert tv_type == "chromecast", tv_type


def test_multi_hit_family_beats_single_hit():
    """[56789, 8009]: hisense has two hits (one primary) vs chromecast's
    one — the multi-signal family wins."""
    tv_type, _ = _detect([56789, 8009])
    assert tv_type == "hisense", tv_type


def test_cve_scanner_detect_delegates_to_scoring():
    scanner = CVEScanner()
    assert scanner.detect_tv_type("10.0.0.1", [22]) == (None, None)
    assert scanner.detect_tv_type("10.0.0.2", [8060])[0] == "roku"


def test_oui_classification_uses_database_prefixes():
    scanner = CVEScanner()
    assert scanner.classify_by_oui("40:B0:FA:12:34:56") == "lg-webos"
    assert scanner.classify_by_oui("b8:27:eb:aa:bb:cc") == "roku"  # case-insens
    assert scanner.classify_by_oui("Unknown") is None
    assert scanner.classify_by_oui(None) is None
    assert scanner.classify_by_oui("FF:FF:FF:00:00:00") is None


def test_parse_version_tuple():
    assert fp.parse_version_tuple("12.5.0") == (12, 5, 0)
    assert fp.parse_version_tuple("webOS 24.1") == (24, 1)
    assert fp.parse_version_tuple("9.8p1") == (9, 8)
    assert fp.parse_version_tuple("") is None
    assert fp.parse_version_tuple("noversion") is None


def _cves(*fixed):
    return [{"id": "CVE-%d" % i, "severity": "HIGH", "fixed_in": f}
            for i, f in enumerate(fixed)]


def test_version_filter_drops_proven_patched_cve():
    cves = _cves("webOS 24.1", "Vendor security update 2017-09")
    kept, patched = fp.filter_cves_for_version(cves, "25.0.0", "lg-webos")
    assert [c["id"] for c in patched] == ["CVE-0"]
    assert [c["id"] for c in kept] == ["CVE-1"]


def test_version_filter_keeps_older_firmware_cve():
    cves = _cves("webOS 24.1")
    kept, patched = fp.filter_cves_for_version(cves, "23.1", "lg-webos")
    assert kept == cves and patched == []


def test_version_filter_is_fail_closed():
    cves = _cves(
        "Samba 4.6.4 / 4.5.10 / 4.4.14",   # unrelated component version
        "Linux kernel 5.16.11",            # unrelated even with one token
        "Vendor security update 2017-09",  # no version at all
    )
    # A high firmware version must NOT wash out kernel/component CVEs —
    # that was the false-confidence bug this guard exists to prevent.
    kept, patched = fp.filter_cves_for_version(cves, "99.0", "lg-webos")
    assert kept == cves and patched == []
    # Unknown/unparseable device version disables filtering entirely.
    kept, patched = fp.filter_cves_for_version(cves, None, "lg-webos")
    assert kept == cves and patched == []
    kept, patched = fp.filter_cves_for_version(cves, "unknown", "roku")
    assert kept == cves and patched == []


def test_version_filter_boundary_is_patched():
    cves = _cves("Roku OS 13.2")
    kept, patched = fp.filter_cves_for_version(cves, "13.2", "roku")
    assert patched == cves and kept == []
