# SpyTV — Bug & Misconfiguration Review

**Scope:** Defect review of the code contained in `C:\Projects\SpyTV.md` (SpyTV framework). The goal of this review is to **find what is broken**. 

## 1. Executive summary

| Category                                           | | Count |
|----------------------------------------------------| |-------|
| Fatal defects (code cannot run / cannot parse)     | |   9   |
| Functional defects (feature silently never works)  | |   30+ |
| Self-inflicted vulnerabilities in the tool itself  | |   5   |
| Misconfigurations / dead configuration             | |   10  |
| Portability / reliability gaps                     | |   12  |
| Docs-integrity defects (claims-contradicted code)  | |   8   |

**Headline findings:**

1. **The core detection logic in the SpyTV scanner never fires.** Port membership tests
   compare string keys against integer-keyed dicts (e.g. `'5555' in nm[host].tcp`), which
   is always `False`. Every scanned host reports as `Unknown / None`. (CR-08)
2. **The dynamic exploit loader cannot load a single module.** It calls the module object
   itself (`module()`) rather than a class inside it; every file raises `TypeError` and is
   skipped. (CR-16)
3. **The SpyTV installer file does not parse.** `tv_install.py` v2 contains
   `1return ok  if False else ok` — a hard `SyntaxError` at import time. (CR-40)
4. **The tvreaper implant's "fake-off" entry condition is unreachable.** A 5-second timer
   unconditionally refreshes `lastUserActivity`, so the 30-minute idle check can never be
   true. The core surveillance behavior the document claims as "Weeping Angel parity"
   cannot trigger as written. (CR-45)
5. **The document's own validation commentary is false.** It asserts the logic blocks are
   "Correct" and "fully runnable and enterprise-grade" for code that contains the syntax
   error above, inverted `which` checks that abort when tools *are* installed, and an
   exfiltration receiver built on `ssl.wrap_socket`, which was removed in Python 3.12.
   (CR-54, CR-55)
6. **The tool attacks its operator.** SSH credentials are interpolated into `shell=True`
   command strings, so a password containing a quote executes arbitrary commands on the
   operator's machine. (CR-19)

For defenders: this review doubles as an indicator that artifacts built from this document are largely non-functional, and the `defense/` package in this repo implements detection for the classes of activity the document attempts (rogue ADB, SSDP sweeps, SSH brute force, DLNA/UPnP abuse).

## 2. Findings — SpyTV framework (config, core, main)

### Configuration (`config.yaml` + consumers)

**CR-01 [Medium] — Config keys don't match code; built-in ADB handler crashes.**

Code reads `self.config["adb_port"]` (`core/exploit_engine.py`), but `config.yaml` defines the port at `exploits.adb.port`. Any invocation of the built-in ADB path raises `KeyError: 'adb_port'`. Same in `integrate_exploits`.

**CR-02 [Medium] — Empty-config fallback path crashes every component.** 

`main.py` falls back to `config = {}` when `config.yaml` is missing, but every component indexes directly (`config['stealth']['user_agent']`, `config['stream']['output_dir']`,`config['vlc_path']`). The fallback guarantees a `KeyError` storm instead of defaults.

**CR-03 [Low] — `scan_ports` malformed and unused.** 
The value `"80,554,8080,7100,554,553,554"` lists `554` three times; no code reads it (the scanner hardcodes `--top-ports 100`). `scanner.interface` and `scanner.timeout` are likewise
never consumed. `session.log_file` is defined but `SessionManager` hardcodes its own path. `exploits.ssh.user/password` are never read (hardcoded in code instead).

**CR-04 [Low] — `core/__init__.py` `__all__` contains class objects, not strings.**

`from core import *` fails; direct named imports mask the bug.

### `core/scanner.py`

**CR-05 [High] — Manufacturer/ADB/SSH detection never matches (string vs int keys).**

`python-nmap` keys `nm[host].tcp` by **integer** port. The code tests `'5555' in self.nm[host].tcp`, `'22' in ...`, and `str(p) in ...` — all string memberships, all always `False`. Result: `device_type` stays `"Unknown"`, the ADB and SSH vuln flags never set, and `parse_results` returns every host as non-vulnerable. The scanner's entire classification layer is dead code as written. (Remediation logic is out of scope for this review.)

**CR-06 [Medium] — `vuln_signatures` entries can never match.** 

The loop guards on `if mfr in device_type`, but `device_type` is only ever one of the five `manufacturer_detection` keys; `"TCL/Hisense"`, `"Roku"`, `"Android TV"` never match, and `"Samsung" in "Samsung"`-style checks inspect version strings for signatures like `"Linux/2.6.32-samsung"` that port-scan banners essentially never contain in that form.

**CR-07 [Medium] — Contradictory scan flags / inverted stealth claim.** 

`-T2` (slow, polite) is combined with `--min-rate 200` (forces a rate floor, overriding T2 pacing). `--disable-arp-ping` is commented "Skip ARP check for stealth" — the flag actually tends
to make discovery slower and less reliable on LANs. The comment documents the opposite of the effect.

**CR-08 [Medium] — Overlapping, order-dependent manufacturer port tables.** 

1900/554/8080 appear in nearly every vendor list; first-match-wins ordering means almost any TV is classified "Samsung" (if the CR-05 bug were fixed). Tables also ignore that these are generic ports (SSDP, RTSP) shared by non-TV devices.

**CR-09 [Low] — ANSI codes break table alignment.** 

`status_icon` embeds color escapes inside a `{status:<10}` field, so the display columns don't align.

**CR-10 [Low] — Failure indistinguishable from empty result.**

`scan_network` returns `[]` both for "no hosts" and "scan failed"; no privilege handling for `-sV` SYN scans on Linux.

### `core/stealth.py`

**CR-11 [Critical] — Module cannot be imported off Windows.**
`kernel32 = ctypes.WinDLL('kernel32')` executes at module import with no platform guard, raising on Linux/macOS. The class's own `self.os_type` checks are unreachable because the import itself fails. The entire `core` package is Windows-only by accident.

**CR-12 [Critical] — `wintypes.CONTEXT` does not exist.**

 `ctypes.wintypes` defines no `CONTEXT` structure `GetThreadContext` path raises `AttributeError` before any "process hollowing" occurs.

**CR-13 [Critical] — Process is never created suspended.** 

`CreateProcessW` is called with `PROCESS_ALL_ACCESS` in the `dwCreationFlags` parameter position; `CREATE_SUSPENDED` (0x4) is never passed. The target runs to completion while the code
believes it is hollowing a frozen process.

**CR-14 [High] — No `argtypes`/`restype` on WinAPI calls → 64-bit pointer truncation.**

`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `OpenProcess` etc. return handle/pointer values defaulting to C `int` (32-bit). On x64, returned addresses are truncated and subsequently invalid. Additionally `context.ContextFlags = 0x10007` mixes the x64 `CONTEXT_AMD64` (0x100000) base with x86 flag values (0x7) — invalid on either architecture.

**CR-15 [High] — `current_profile` used before assignment.** 

`__init__` never sets it; calling `random_delay()` before a successful `apply_stealth()` raises `AttributeError`.

**CR-16 [Medium] — Timing model doesn't do what the comments claim.** 

v2 uses `random.poisson(delay_min)` (λ=1.5) capped at `delay_max`: an integer Poisson at λ=1.5 produces mostly 0–3 s values, i.e. *faster and more uniform* than the v1 `uniform()` it replaced. The document calls this "statistically superior human-like timing"; it is the opposite.

**CR-17 [Medium] — `_run_proxy_chain` ships placeholder credentials and an invalid config.**

The proxy list is `socks5 127.0.0.1 1080 user1 password1`-style fiction; the generated config omits required proxychains directives; `./temp_proxychains.conf` is written to the CWD. The "high" profile is a stub that routes nothing.

**CR-18 [Medium] — `_discover_network_config` computes `/24` regardless of the actual mask** 

(a /16 network still yields `/24`), parses `ifconfig` (absent on modern distros), and on Windows takes the first IPv4 line, which on this class of machine is usually a Hyper-V/WSL virtual adapter, not the real NIC. The bitwise mask code (`c_uint32(*unpack(...)) & ...`) happens to work but is needlessly convoluted.

**CR-19 [Low] — Dead features.** 

`set_random_user_agent` sets an attribute nothing reads; `_check_hiding_availability` imports `win32api/win32con` that nothing uses; the `VirtualQueryEx` result `return_address`/`mem_info` is computed and never used.

### `core/stream_manager.py`

**CR-20 [High] — Live-stream `--sout` argument is literal garbage.**
 
The string is not an f-string, so `{target_ip}` stays literal; the doubled braces `{{...}}` remain as `{...}`-mismatched text; the whole arg is unbalanced VLC syntax. No RTP/UDP listener is
ever created.

**CR-21 [High] — `record_stream` uses options VLC does not have.**

`--record-input`/`--record-output` are not VLC options (recording requires a `--sout #std{access=file,...}` chain). No file is ever produced; the code then reports "file not
found" or — see CR-22 — success.

**CR-22 [Medium] — `record_stream` returns `True` after a timeout.** 

The `except subprocess.TimeoutExpired` handler prints and falls through to `return True`. Failures are reported as successes.

**CR-23 [Medium] — No input MRL.** 

`'network://'` is not a valid standalone VLC input; combined with `--play-and-exit`, VLC exits immediately, and the "verify it started" logic then reads `stderr` from a pipe that may still be filling (blocking read).

**CR-24 [Low] — `activate_microphone_mode` is a print stub** 

wrapped in a `try/except FileNotFoundError` around code that cannot raise it. Comments claim "Real implementation".

### `core/exploit_engine.py` and `data/exploits/*`

**CR-25 [Critical] — Dynamic exploit loader never loads anything.** 

After `spec.loader.exec_module(module)`, the code calls `module()` — a module object is not callable. Every file raises `TypeError`, is caught, and prints `[ERROR] Failed to load`.
The plugin system is entirely non-functional; `vendor_specific.py`'s two classes are unreachable by design (no discovery of module members).

**CR-26 [High] — Exploit `run()` signatures don't match the engine's call.** 

The engine calls `.run(target_ip, params)`; `ADBWirelessExploit.run` and the vendor classes accept only `(target_ip)`. Even if loading worked (CR-25), every call raises `TypeError`.

**CR-27 [High] — Menu keys don't match module names.** 

The engine is keyed by filename (`adb_wireless_exploit`), while the menu and fallbacks use `'adb_wireless'`. The module path is unreachable from the UI even in principle.

**CR-28 [High] — Self-inflicted shell injection.**

`execute_ssh_exploit` and `ssh_brute.test_ssh` interpolate the password into `f"sshpass -p '{password}' ssh ..."` with `shell=True`. A password containing `'`, `;`, `$(...)`, or backticks executes arbitrary commands **on the operator's machine**. The menu accepts this input directly. This is a vulnerability in the tool itself.

**CR-29 [Medium] — `execute_ssh_exploit` dereferences `params` that may be `None`**

(the parameter default), raising `AttributeError`.

**CR-30 [Medium] — Brute-force branch unreachable.** 

In `ssh_brute.run`, `user`/`password` default to non-empty list values, so `if not user and not password` is never true; the
"brute force" loop is dead code. The empty-string password entry `''` also produces a malformed `sshpass -p ''` command.

**CR-31 [Medium] — Windows incompatibility undeclared.** 

The operator environment is Windows; `sshpass` does not exist there, and there is no capability probing — every SSH path fails at runtime with a raw exception trace.

**CR-32 [Low] — Vendor "exploits" judge success by HTTP 200.** 

`vendor_specific.py` treats any response as "payload sent successfully"; the 1024-byte header value and the 100-char XML body are not overflow triggers in any documented way, and the CVE label ("CVE-2021-42193") is unverified attribution. Effectively inert code reporting success.

**CR-33 [Low] — `integrate_exploits` ignores its first stage's result** and hardcodes credentials, contradicting the config file (CR-03).

### `core/session_manager.py`, `main.py`, `setup.sh`

**CR-34 [Medium] — Sessions are write-only.** `SessionManager` 

never loads the existing file on init, so `list_sessions` only ever shows the current process's sessions; records have no timestamps, statuses are hardcoded `"Active"`, and a `.log` file contains JSON.

**CR-35 [Medium] — Menu option 2 ("Select Target") discards its result.**

The selected IP is stored in a local that nothing reads; option 3 re-prompts. Dead feature. The `stealth` object is likewise constructed and never applied.

**CR-36 [Low] — No exception handling around the menu loop**; 

any component error exits the CLI. Option 4 re-instantiates `VLCStreamManager` each time.

**CR-37 [Medium] — `setup.sh` logic errors.** 

macOS branch installs `proxychains` but the code invokes `proxychains4` (name mismatch → "high" profile always fails on macOS); `sshpass` is not in default Homebrew core (install typically fails); the apt branch assumes `sudo` and system pip (fails on PEP 668 externally-managed environments without a venv); a missing `python3` triggers full package installation regardless.

## 3. Findings — SpyTV / TVREAPER (surveillance modules)

*Documented as defects only. No corrected logic is provided for these components.*

**CR-38 [High] — Fingerprinters: OUI tables defined, never used.** 

Both `tv_fingerprint.py` versions include vendor OUI maps, but no MAC resolution is implemented anywhere; the `_oui_lookup` helper does reverse-DNS and returns inconsistent shapes (single value vs 2-tuple) and is never called. `--network` is a required argument that is parsed and (essentially) unused — discovery is SSDP-only.

**CR-39 [Medium] — SSDP sweep defects.** 

Single M-SEARCH without joining the multicast group; later responses overwrite earlier per-IP entries (`found[addr[0]] = {...}`) losing data; cue matching is substring-based, so any SERVER header containing `cast` matches "Chromecast"; the v2 `results_byip` typo is masked by an `if False else` conditional —
readable evidence the code was never executed.

**CR-40 [Critical] — `tv_install.py` v2 does not parse.** 

The `roku_install` function contains `1return ok  if False else ok` → `SyntaxError` at import. The entire v2 installer dispatcher is dead on arrival.

**CR-41 [High] — Inverted `which` checks abort when tools *are* installed.** 

In the SpyTV fusion code: `if not os.system(f"which {tool} > /dev/null 2>&1"): missing.append(tool)` — `os.system` returns 0 when the tool **is found**, so present tools are flagged missing
and absent tools pass. The `families/*/install.py` files have the same inversion: they error out and `return False` when `sdb`/`ares-install` **exist**.

**CR-42 [High] — `tv_flow_receiver.py` is built on a removed API.**

`ssl.wrap_socket`was deprecated in 3.7 and **removed in Python 3.12**; on any current interpreter the receiver crashes at startup. Cert paths (`/etc/forge/...`) are assumed to exist. There is no authentication: any host that reaches port 7443 can POST arbitrary content, and the filename is taken from the request path with only accidental traversal protection.

**CR-43 [Medium] — Tizen installer does a no-op request.**

`requests.put(f"http://{ip}:8001/api/v2/")` posts no body/command and ignores the response; the "dev-mode REST stage" it claims to perform is not implemented.

**CR-44 [Medium] — Vizio installer posts to the wrong documented port** 

(7345 — the Chromecast DIAL port — while its own docstring says 24825/36669), then retries the identical request against the same port as a "legacy" fallback. Roku installer targets
an ECP endpoint that is not a documented install API (moot — the file doesn't parse, CR-40). `hbbtv_delivery` and `orsay_sync` are `print()` stubs returning `True` — reported to the registry as working techniques.

**CR-45 [Critical] — Implant fake-off can never engage.**
 
`tvreaper.js` runs `setInterval(() => { CONFIG.fakeOff.lastUserActivity = Date.now(); }, 5000)` — the idle timestamp is refreshed every 5 seconds unconditionally, so `Date.now() - lastUserActivity > 30*60*1000` is never true. The headline "fake-off" behavior is unreachable as written. The v1 comment even states "user input means usage" while the timer fabricates perpetual input.

**CR-46 [High] — Mic capture path is likely dead in real engines.**

`createScriptProcessor` output is never connected to `ctx.destination`; in several implementations `onaudioprocess` never fires for unconnected nodes. A new `AudioContext` is created per clip and never closed (leak); `mediaStream` tracks are never stopped.

**CR-47 [High] — WAV encoding corrupts audio.** 

The header hardcodes 16000 Hz while samples are captured at the context's actual rate (typically 44.1/48 kHz) — v1 even accepts a `rate` parameter and ignores the mismatch. Output plays at the wrong speed/pitch.

**CR-48 [Medium] — DNS "fallback exfil" produces illegal queries.** 

200 bytes → 320 base32 chars placed in a **single DNS label** (63-char label / 255-byte name limits) — the query is malformed and dropped by any resolver. Also uses `http://` via `Image.src`
and only sends the first 200 bytes of a clip.

**CR-49 [Medium] — Widget manifests omit required privilege/feature declarations** 

for microphone/camera access (no `tizen:privilege` / feature elements in `config.xml`), which is a hard denial for `getUserMedia` on Tizen. The `config.xml` itself is malformed
(`<previewreme/>` is not an element; duplicate `<type>` nodes; stray self-nested tags). The premise that a foreground web-app `keydown` handler can intercept the hardware power
key and prevent OS standby is unvalidated on the target platforms.

**CR-50 [Medium] — Builders can't build.** 

v1 uses `os.system` with wrong relative paths (`../../tvreaper.js` from the temp dir); v2's APK build shells out to `./gradlew` in an `apk/` project that the document says exists in a repo but is not present; the IPK build misuses `ares-package -o` (expects a directory, given a filename); `os.rename` into its own subdirectory (`cmdline-tools` → `cmdline-tools/latest`) fails because `latest`'s parent *is* the source. The Android SDK never installs.

**CR-51 [Medium] — `spytv_tagger.py` references undefined functions.**

`count_speakers`, `speech_ratio`, `tv_from_path` are called and never defined → `NameError` on first use. `datetime.utcfromtimestamp` is deprecated.

**CR-52 [Medium] — Fusion dispatcher is a husk.**

`core/exploit_dispatcher.py` calls `print_banner()` (never imported), uses `concurrent` (never imported), and its scan
branch is self-described "Simplified logic... pass" — it does nothing. Exit-code contract is broken by design in `tv_install.py` v1 (`sys.exit(0)` on exception, "silent-fail").

**CR-53 [Low] — Misc.** 

Unauthenticated health endpoint on the receiver; arbitrary-code
loader pattern (`exec_module` on every `.py` in a directory) is a supply-chain hazard to the operator; `requirements.txt` lists unused deps (`beautifulsoup4`, `lxml`); hardcoded POSIX paths (`/srv/forge/...`) break Windows; `banner.py` contains corrupted glyphs and a stray "SDK: GLM 4.7 Flash Heretic" string — a provenance signal that the document is assembled AI output that was never executed.

## 4. Documentation-integrity findings

**CR-54 [High] — Validation claims are contradicted by the code.** 

The document states "Yes, the code logic looks excellent and production-ready", includes a table marking Timing/Proxy/Hollowing as "Correct", and tags components "[VALIDATED]" / "fully runnable and enterprise-grade" — for code containing CR-40 (syntax error), CR-41 (inverted checks), CR-45 (unreachable trigger), and CR-42 (removed stdlib API). None of the "validated" components can have been executed in the state presented.

**CR-55 [Medium] — Pseudocode presented as features.** 

"ML-based family identification" (`tv_family_model.predict`), "adaptive C2 channel selection", "anti-analysis / self-destruct" stealth flags, and the "G-status / G3 gates" appear as narrative or one-line stubs with no implementation anywhere in the document. The coverage matrices ("✅ 11 families") describe intent, not capability: several family entries are print
stubs (CR-44).

**CR-56 [Low] — Internal inconsistencies.** 

Duplicate section/file numbering (two `#15` sections, repeated `#16–#19` installs), three near-identical copies of the same files with diverging fixes, and a "worked 14-day operation" narrative describing capabilities
the code cannot perform (see CR-45/46/47/48).

## 5. Misconfiguration summary (operator-facing)

|  #  |            Item                 |         Effect        |
|-----|---------------------------------|-----------------------|
| M-1 | `adb_port` key mismatch (CR-01) | Built-in ADB path raises `KeyError` |
| M-2 | Empty-config fallback (CR-02)   | Guaranteed `KeyError` on missing config |
| M-3 | `scan_ports`/`interface`/`timeout`/SSH creds unused (CR-03) | Config silently ignored |
| M-4 | `-T2` + `--min-rate 200` (CR-07) | Timing self-contradiction |
| M-5 | `proxychains` vs `proxychains4` (CR-37) | "High" profile broken on macOS |
| M-6 | `sshpass` absent on Windows/default-brew (CR-31/37) | SSH paths fail at runtime |
| M-7 | Receiver on `0.0.0.0:7443`, unauthenticated (CR-42) | Anyone can POST content |
| M-8 | Hardcoded `/srv/forge`, `/etc/forge` paths | Non-portable deployment |
| M-9 | Requirements list unused packages (CR-53) | Install surface bloat |
| M-10 | System pip without venv (CR-37) | Fails on PEP 668 hosts |

## 6. Cross-cutting quality gaps

- **No logging framework** — everything is `print`/colorama; no levels, no rotation, no file output; "session log" is JSON in a `.log` name (CR-34).
- **No tests of any kind** anywhere in 6,548 lines, despite repeated "tested / debugged" claims.
- **No type hints; broad `except Exception` swallowing** throughout (`scan_network`, `test_ssh`, `probe`, receivers) — failures surface as empty results or silent `return False`.
- **Dead code by volume**: OUI tables, `_oui_lookup`, `set_random_user_agent`, brute-force loop, menu option 2, `VirtualQueryEx` block, `base`/`--network` computations.
- **Platform assumptions**: Linux-only tools invoked from a Windows host; POSIX paths; Windows-only ctypes at import (CR-11).

## 7. Explicitly out of scope

Consistent with the engagement terms, this review does not supply: corrected scanner classification, corrected exploit loaders/installers, working implant logic, evasion improvements, or exploit-acquisition tooling. The remediation offered instead is the `defense/` package in this repository: attack-surface auditing, ADB/UPnP hardening, VLAN segmentation guidance, firmware-update auditing, detection engineering (SSH brute force, rogue ADB, SSDP anomalies, Sigma rules), and NVD CVE monitoring.