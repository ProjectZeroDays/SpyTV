# Smart TV Vulnerability Whitepaper — 90-day lookback

_Generated 2026-10-03T20:23:14+00:00 by the SpyTV defensive toolkit._

## Scope

- **Lookback window:** 90 days
- **Keyword scope:** smart tv, smart television, android tv, google tv, tizen, webos, roku, fire tv, smartcast, hbbtv, chromecast, vidaa
- **CVEs found:** 14
- **Severity split:** CRITICAL 3, HIGH 8, MEDIUM 2, UNRATED 1
- **With public exploit references:** 0

## Executive summary

Over the last 90 days, NVD published 14 vulnerability records matching the smart TV platform keywords tracked by this toolkit. Smart TVs sit on living-room and boardroom networks with microphones, cameras, and a path onto the LAN; their patch cadence is slower than phones or laptops by design. The recommended posture is unchanged regardless of CVE count: automatic updates on, the TV on a segmented VLAN, management surfaces closed, and the detection stack watching the entry paths. Each entry below maps to those controls.

## Vulnerability index

| CVE | Severity | Score | Published | Platforms | Public exploit ref |
|---|---|---|---|---|---|
| CVE-2026-16416 | CRITICAL | 9.3 | 2026-07-21 | Chromecast / cast-enabled devices | No |
| CVE-2026-17672 | CRITICAL | 9.6 | 2026-07-30 | Chromecast / cast-enabled devices | No |
| CVE-2026-78939 | CRITICAL | 9.6 | 2026-08-25 | Chromecast / cast-enabled devices | No |
| CVE-2026-16414 | HIGH | 7.8 | 2026-07-21 | Chromecast / cast-enabled devices | No |
| CVE-2026-79054 | HIGH | 8.3 | 2026-08-25 | Chromecast / cast-enabled devices | No |
| CVE-2026-79121 | HIGH | 8.3 | 2026-08-25 | Chromecast / cast-enabled devices | No |
| CVE-2026-79202 | HIGH | 8.8 | 2026-08-25 | Chromecast / cast-enabled devices | No |
| CVE-2026-79224 | HIGH | 8.3 | 2026-08-25 | Chromecast / cast-enabled devices | No |
| CVE-2026-79292 | HIGH | 8.3 | 2026-08-25 | Chromecast / cast-enabled devices | No |
| CVE-2026-87588 | HIGH | 8.8 | 2026-09-09 | Chromecast / cast-enabled devices | No |
| CVE-2026-95372 | HIGH | 8.3 | 2026-09-29 | Chromecast / cast-enabled devices | No |
| CVE-2026-17903 | MEDIUM | 5.4 | 2026-07-30 | Chromecast / cast-enabled devices | No |
| CVE-2026-85084 | MEDIUM | 6.3 | 2026-09-03 | Samsung Tizen TVs | No |
| CVE-2026-15570 | UNRATED | — | 2026-08-07 | Smart TVs (generic) | No |

## CVE-2026-16416

- **Severity:** CRITICAL (CVSS 9.3)
- **Published:** 2026-07-21T23:16:59.170
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Integer overflow in Chromecast in Google Chrome prior to 150.0.7871.182 allowed a local attacker to potentially perform a sandbox escape via malicious network traffic. (Chromium security severity: High)

**Recommended actions:**
1. Critical severity: schedule an emergency firmware update window.
2. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
3. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
4. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
5. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/07/stable-channel-update-for-desktop_0256605430.html
- https://issues.chromium.org/issues/520172356

## CVE-2026-17672

- **Severity:** CRITICAL (CVSS 9.6)
- **Published:** 2026-07-30T01:16:29.330
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Insufficient validation of untrusted input in Chromecast in Google Chrome prior to 151.0.7922.72 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

**Recommended actions:**
1. Critical severity: schedule an emergency firmware update window.
2. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
3. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
4. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
5. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/07/stable-channel-update-for-desktop_0887107924.html
- https://issues.chromium.org/issues/513375270

## CVE-2026-78939

- **Severity:** CRITICAL (CVSS 9.6)
- **Published:** 2026-08-25T21:17:49.723
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Use after free in Chromecast in Google Chrome prior to 152.0.7977.65 allowed a remote attacker who had compromised the renderer process to execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: High)

**Recommended actions:**
1. Critical severity: schedule an emergency firmware update window.
2. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
3. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
4. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
5. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0256176589.html
- https://issues.chromium.org/issues/513261751

## CVE-2026-16414

- **Severity:** HIGH (CVSS 7.8)
- **Published:** 2026-07-21T23:16:58.943
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Insufficient validation of untrusted input in Chromecast in Google Chrome prior to 150.0.7871.182 allowed a local attacker to potentially perform a sandbox escape via malicious network traffic. (Chromium security severity: High)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/07/stable-channel-update-for-desktop_0256605430.html
- https://issues.chromium.org/issues/517651910

## CVE-2026-79054

- **Severity:** HIGH (CVSS 8.3)
- **Published:** 2026-08-25T21:18:01.263
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Use after free in Chromecast in Google Chrome prior to 152.0.7977.65 allowed a remote attacker who had compromised the renderer process to execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0256176589.html
- https://issues.chromium.org/issues/516764384

## CVE-2026-79121

- **Severity:** HIGH (CVSS 8.3)
- **Published:** 2026-08-25T21:18:07.210
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Improper input validation in Chromecast in Google Chrome prior to 152.0.7977.65 allowed a remote attacker who had compromised the renderer process to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0256176589.html
- https://issues.chromium.org/issues/516777082

## CVE-2026-79202

- **Severity:** HIGH (CVSS 8.8)
- **Published:** 2026-08-25T21:18:14.047
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Use after free in Chromecast in Google Chrome prior to 152.0.7977.65 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: High)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0256176589.html
- https://issues.chromium.org/issues/521285077

## CVE-2026-79224

- **Severity:** HIGH (CVSS 8.3)
- **Published:** 2026-08-25T21:18:16.530
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Use after free in Chromecast in Google Chrome prior to 152.0.7977.65 allowed a remote attacker who had compromised the renderer process to execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: Critical)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0256176589.html
- https://issues.chromium.org/issues/516988476

## CVE-2026-79292

- **Severity:** HIGH (CVSS 8.3)
- **Published:** 2026-08-25T21:18:23.417
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Integer overflow in Chromecast in Google Chrome prior to 152.0.7977.65 allowed a remote attacker who had compromised the renderer process to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: High)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/08/stable-channel-update-for-desktop_0256176589.html
- https://issues.chromium.org/issues/517519352

## CVE-2026-87588

- **Severity:** HIGH (CVSS 8.8)
- **Published:** 2026-09-09T01:17:16.683
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Use after free in Chromecast in Google Chrome prior to 153.0.8010.36 allowed a remote attacker to execute arbitrary code inside the sandbox via a crafted HTML page. (Chromium security severity: Medium)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop_0808145027.html
- https://issues.chromium.org/issues/495515356

## CVE-2026-95372

- **Severity:** HIGH (CVSS 8.3)
- **Published:** 2026-09-29T18:17:31.130
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Use after free in Chromecast in Google Chrome prior to 154.0.8037.57 allowed a remote attacker who had compromised the renderer process to potentially execute arbitrary code outside the sandbox via a crafted HTML page. (Chromium security severity: High)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop_0856730748.html
- https://issues.chromium.org/issues/534997484

## CVE-2026-17903

- **Severity:** MEDIUM (CVSS 5.4)
- **Published:** 2026-07-30T01:16:54.353
- **Platforms:** Chromecast / cast-enabled devices
- **Matched keywords:** chromecast
- **Public exploit reference:** No

Insufficient policy enforcement in Chromecast in Google Chrome prior to 151.0.7922.72 allowed an attacker on the local network segment to inject scripts or HTML into a privileged page via malicious network traffic. (Chromium security severity: Low)

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://chromereleases.googleblog.com/2026/07/stable-channel-update-for-desktop_0887107924.html
- https://issues.chromium.org/issues/497277880

## CVE-2026-85084

- **Severity:** MEDIUM (CVSS 6.3)
- **Published:** 2026-09-03T13:06:20.143
- **Platforms:** Samsung Tizen TVs
- **Matched keywords:** tizen
- **Public exploit reference:** No

Out-of-bounds Write and Improper Validation of Array Index vulnerability in Samsung Open Source TizenFX Samsung/TizenFX allows Overflow Buffers.

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://github.com/Samsung/TizenFX/pull/7814
- https://github.com/Samsung/TizenFX/pull/7815

## CVE-2026-15570

- **Severity:** UNRATED
- **Published:** 2026-08-07T14:16:56.890
- **Platforms:** Smart TVs (generic)
- **Matched keywords:** smart tv
- **Public exploit reference:** No

An improper restriction of URL schemes and destinations in the SmartCenter browserseturl command in the Telefunken TE24553B45V2DZ Smart TV running on the Vestel MB181 / Voltron181 / TiVo OS platform allows an attacker with access to the same local network to cause the embedded browser to issue requests to unintended loopback/internal destinations, including 127.0.0.1 addresses. In demonstrated sce

**Recommended actions:**
1. Apply the vendor firmware update (see wiki: Hardening Guide — firmware audit).
2. Confirm the device sits on a segmented IoT VLAN (vlan_segmentation) so a media-stack bug cannot pivot to trusted hosts.
3. Close unused management surfaces on the device — network ADB, dev mode, UPnP AV (adb_disable, upnp_close).
4. Watch for exploitation indicators with the detection stack (wiki: Detection Guide); the entry paths are rogue ADB connections, SSH failures, and SSDP sweeps.

**References (as listed by NVD):**
- https://firebasestorage.googleapis.com/v0/b/vestel-shield.firebasestorage.app/o/PRODUCTION%2F4%2FVSA-4.pdf?alt=media&token=61fb45d3-b88e-4810-a620-693a1c693db4
- https://vestelinternational.com/security-advisories
