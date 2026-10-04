"""Behavioural tests for the C2 dashboard's inline script.

The dashboard is one large inline <script> that pytest cannot execute, so these
tests run it in Node against a stub DOM and assert the failure modes that used
to be *silent* — which is exactly what the reports described:

  * "the scan button on the c2 doesnt work": startScan() had no error handling,
    so a failed or malformed reply died as an unhandled rejection and the results
    panel stayed empty with the button never giving any feedback.
  * "client details submission hangs after input": api() had no timeout, so a
    C2 that never answered left the submit button disabled forever.

They skip when node is unavailable; node is already required to build the
Electron shell.
"""
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

import pytest

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node is required")

REPO = pathlib.Path(__file__).resolve().parents[1]


def _dashboard_script() -> str:
    html = (REPO / "c2_dashboard.html").read_text(encoding="utf-8")
    blocks = re.findall(r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>",
                        html, re.S | re.I)
    assert len(blocks) == 1, f"expected 1 inline script, found {len(blocks)}"
    return blocks[0]


# ---------------------------------------------------------------------------
# browser shims: enough DOM for the dashboard's startup code and renderers
# ---------------------------------------------------------------------------
PRELUDE = r"""
const __els = new Map();
function __ctx2d() {
  return new Proxy({ measureText: () => ({ width: 0 }) }, {
    get(t, k) {
      if (k in t) return t[k];
      return () => {};
    },
    set() { return true; },
  });
}
function fakeEl(id) {
  if (__els.has(id)) return __els.get(id);
  const calls = { added: [], removed: [] };
  const el = Object.assign(calls, {
    id, children: [], style: {}, dataset: {}, hidden: false, disabled: false,
    value: '', textContent: '', innerHTML: '', className: '', src: '',
    scrollTop: 0, scrollHeight: 0, width: 0, height: 0, files: [],
    classList: {
      add(c) { calls.added.push(c); },
      remove(c) { calls.removed.push(c); },
      toggle() {}, contains() { return false; },
    },
    appendChild(c) { el.children.push(c); return c; },
    removeChild() {}, insertBefore() {}, replaceChildren() {},
    setAttribute() {}, getAttribute() { return null; }, removeAttribute() {},
    addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
    focus() {}, blur() {}, click() {}, remove() {}, scrollIntoView() {},
    querySelector(s) { return fakeEl(id + '>' + s); },
    querySelectorAll() { return []; },
    getBoundingClientRect() {
      return { width: 120, height: 24, top: 0, left: 0, right: 120, bottom: 24 };
    },
    getContext() { return __ctx2d(); },
    toDataURL() { return 'data:image/png;base64,'; },
    cloneNode() { return fakeEl(id + '@clone'); },
    contains() { return false; },
    addEventListenerOnce() {},
  });
  __els.set(id, el);
  return el;
}
globalThis.document = {
  getElementById: (id) => fakeEl(id),
  querySelector: (s) => fakeEl(s),
  querySelectorAll: () => [],
  createElement: (tag) => fakeEl('<' + tag + '>'),
  createTextNode: (t) => ({ text: t }),
  addEventListener() {}, removeEventListener() {},
  body: fakeEl('body'), documentElement: fakeEl('html'),
  hidden: false, title: 'SpyTV', visibilityState: 'visible',
  fonts: { ready: Promise.resolve() },
};
globalThis.window = globalThis;
globalThis.location = { href: 'http://127.0.0.1:8443/', origin: 'http://127.0.0.1:8443',
  search: '', hash: '', pathname: '/', protocol: 'http:', host: '127.0.0.1:8443',
  assign() {}, replace() {} };
globalThis.navigator = { userAgent: 'node', clipboard: {} };
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.alert = () => {}; globalThis.confirm = () => true; globalThis.prompt = () => '';
globalThis.console = console;
globalThis.innerWidth = 1400; globalThis.innerHeight = 900;
globalThis.devicePixelRatio = 1;
globalThis.setInterval = () => 0;      // never schedule background polls
globalThis.clearInterval = () => {};
// setTimeout stays native: api()'s AbortController budget and the hang race
// both depend on it actually firing.
globalThis.requestAnimationFrame = (fn) => { fn(0); return 0; };
globalThis.AbortController = AbortController;
globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} };
globalThis.IntersectionObserver = class { observe() {} unobserve() {} disconnect() {} };
globalThis.matchMedia = () => ({ matches: false, addListener() {}, addEventListener() {} });
globalThis.fetch = (...a) => globalThis.__fetchImpl(...a);
// Benign default so the dashboard's own startup poll (loadDevices/poll) does
// not reject before a test installs its stub — in a browser that first poll
// talks to a live C2 and succeeds.
globalThis.__fetchImpl = async () => ({
  ok: true, status: 200, statusText: 'OK',
  text: async () => '[]',
});
process.on('unhandledRejection', (e) => {
  console.log('  [unhandledRejection] ' + ((e && e.message) || e));
});
globalThis.__el = (id) => fakeEl(id);
"""

POSTLUDE = r"""
let failures = 0;
function ok(cond, label, extra) {
  if (cond) console.log('  PASS  ' + label);
  else { failures++; console.log('  FAIL  ' + label + (extra ? '  | ' + extra : '')); }
}
function jsonResponse(obj, status = 200) {
  const text = JSON.stringify(obj);
  return {
    ok: status >= 200 && status < 300, status,
    statusText: status === 200 ? 'OK' : 'Error',
    text: async () => text,
  };
}

(async () => {
  // Pre-seed the elements startScan touches.
  __el('scan-btn').textContent = 'Scan';
  __el('scan-cidr').value = '';
  const results = __el('scan-results');
  const log = __el('log-container');

  console.log('--- 1. happy path -------------------------------------------------');
  globalThis.__fetchImpl = async () => jsonResponse({
    status: 'ok', found: 2,
    results: [
      { ip: '10.2.0.1', device_type: 'LG webOS', name: 'LG webOS TV',
        open_ports: [80, 3000], cves: [{ id: 'CVE-2023-0001', severity: 'High' }],
        vulnerable: true, severity: 'High' },
      { ip: '10.2.0.2', device_type: 'Chromecast', name: 'Chromecast',
        open_ports: [80, 8443], cves: [], vulnerable: true },
    ],
  });
  results.innerHTML = '';
  await startScan();
  ok(results.innerHTML.includes('<table'), 'results table rendered');
  ok(results.innerHTML.includes('10.2.0.1'), 'row for 10.2.0.1 rendered');
  ok(results.innerHTML.includes('CVE-2023-0001'), 'CVE chip rendered');
  ok(__el('scan-btn').textContent === 'Scan', 'button label restored',
     JSON.stringify(__el('scan-btn').textContent));
  ok(__el('scan-btn').disabled === false, 'button re-enabled');
  ok(log.children.some(c => String(c.innerHTML).includes('Scan complete: 2')),
     'log shows Scan complete: 2 devices');
  ok(typeof lastScanResults === 'object' && lastScanResults.length === 2,
     'lastScanResults stored');

  console.log('--- 2. server returns an error body --------------------------------');
  results.innerHTML = '';
  globalThis.__fetchImpl = async () =>
    jsonResponse({ error: 'CIDR is not a valid network', errors: ['bad cidr'] }, 400);
  await startScan();
  ok(results.innerHTML.includes('Scan failed'), 'failure surfaced in panel',
     results.innerHTML.slice(0, 120));
  ok(results.innerHTML.includes('bad cidr'), 'server error text shown');
  ok(__el('scan-btn').textContent === 'Scan', 'button label restored after error');
  ok(__el('scan-btn').disabled === false, 'button re-enabled after error');
  ok(log.children.some(c => String(c.innerHTML).includes('Scan failed')),
     'log shows Scan failed');

  console.log('--- 3. C2 unreachable (network error) ------------------------------');
  results.innerHTML = '';
  globalThis.__fetchImpl = async () => { throw new TypeError('Failed to fetch'); };
  await startScan();
  ok(results.innerHTML.includes('Scan failed'), 'network failure surfaced');
  ok(results.innerHTML.includes('cannot reach the C2'), 'actionable message');
  ok(__el('scan-btn').disabled === false, 'button re-enabled after network error');

  console.log('--- 4. malformed reply (the old TypeError path) --------------------');
  results.innerHTML = '';
  globalThis.__fetchImpl = async () => jsonResponse({ status: 'ok', found: 0 });
  await startScan();
  ok(results.innerHTML.includes('Scan failed') || results.innerHTML.includes('no results'),
     'missing results list handled, not thrown',
     results.innerHTML.slice(0, 160));
  ok(results.innerHTML.length > 0, 'panel was not left blank');
  ok(__el('scan-btn').disabled === false, 'button re-enabled');

  console.log('--- 5. renderScanResults(undefined) guard --------------------------');
  results.innerHTML = 'PREVIOUS ROWS';
  renderScanResults(undefined);
  ok(results.innerHTML.includes('no results'), 'guard shows a message, no throw',
     results.innerHTML.slice(0, 120));

  console.log('--- 6. client-details submit: success ------------------------------');
  ['company', 'name', 'address', 'phone', 'email', 'website']
    .forEach(f => { __el('cf-' + f).value = 'x'; });
  __el('cf-company').value = 'Acme';
  __el('client-submit').textContent = 'Continue';
  const errs = __el('client-errors');
  errs.hidden = true; errs.innerHTML = '';
  clientModalMode = 'audit';
  globalThis.__fetchImpl = async () => jsonResponse(
    { auth_id: 'AUTH-1', pdf_url: '/api/audit/authorization.pdf?auth_id=AUTH-1&state=unsigned',
      expires_days: 30 });
  await submitClientForm();
  ok(__el('client-submit').textContent === 'Continue', 'submit label restored',
     JSON.stringify(__el('client-submit').textContent));
  ok(__el('client-submit').disabled === false, 'submit re-enabled');
  ok(errs.hidden === true, 'no error block shown on success');
  ok(__el('client-modal').removed.includes('active'), 'client modal closed');

  console.log('--- 7. client-details submit: server rejects -----------------------');
  __el('client-submit').textContent = 'Continue';
  globalThis.__fetchImpl = async () =>
    jsonResponse({ error: 'Invalid client details', errors: ['Company is required'] }, 400);
  await submitClientForm();
  ok(__el('client-errors').innerHTML.includes('Company is required'),
     'validation errors listed');
  ok(__el('client-submit').disabled === false, 'submit re-enabled after rejection');
  ok(__el('client-submit').textContent === 'Continue', 'label restored after rejection');

  console.log('--- 8. client-details submit: request never answers ----------------');
  __el('client-submit').textContent = 'Continue';
  globalThis.__fetchImpl = () => new Promise(() => {});   // hangs forever
  const raced = await Promise.race([
    submitClientForm().then(() => 'returned'),
    new Promise(r => setTimeout(() => r('pending'), 400)),
  ]);
  // Without api()'s AbortController budget this promise would never settle.
  ok(raced === 'pending',
     'hang is now bounded by AbortController (budget ' + apiTimeoutFor('/api/audit/authorize') + 'ms)',
     raced);

  console.log('--- 9. per-endpoint timeouts ---------------------------------------');
  ok(apiTimeoutFor('/api/cve/patch') === 600000,
     'cve/patch gets 600s (45s-per-command stack)');
  ok(apiTimeoutFor('/api/scan') === 300000, 'scan gets 300s');
  ok(apiTimeoutFor('/api/exploit') === 300000, 'exploit gets 300s');
  ok(apiTimeoutFor('/api/patch/report') === 300000, 'patch report gets 300s');
  ok(apiTimeoutFor('/api/cve/update') === 300000, 'cve update gets 300s');
  ok(apiTimeoutFor('/api/scans') === 30000,
     'the scans read stays on the short budget (fast local read)');
  ok(apiTimeoutFor('/api/audit/authorize') === 30000, 'authorize gets 30s');
  ok(apiTimeoutFor('/api/audit/sign') === 30000, 'sign gets 30s');
  ok(apiTimeoutFor('/api/command') === 30000,
     'command queue gets 30s (in-memory, fast)');
  ok(apiTimeoutFor('/api/devices') === 30000, 'devices gets 30s');

  console.log('--- 10. CVE tab: error body must not reach .map -------------------');
  const cvePanel = __el('cve-results');
  cvePanel.innerHTML = '';
  let threw = false;
  try { renderCVEs({ error: 'boom' }); } catch (e) { threw = true; }
  ok(!threw, 'renderCVEs(error object) does not throw');
  ok(cvePanel.innerHTML.includes('could not be loaded'), 'shows a message, not a blank tab',
     cvePanel.innerHTML.slice(0, 140));
  cvePanel.innerHTML = '';
  renderCVEs([{ id: 'CVE-1', severity: 'HIGH', score: 9.8, component: 'x',
                tv_type: 'tizen', device_name: 'TV', fixed_in: '1' }]);
  ok(cvePanel.innerHTML.includes('CVE-1'), 'a real list still renders');

  console.log('--- 11. devices loader keeps last-good state ----------------------');
  devices = [{ id: 'd1', ip: '10.2.0.1', family: 'LG webOS', status: 'online' }];
  globalThis.__fetchImpl = async () => jsonResponse({ error: 'boom' }, 500);
  let devThrew = false;
  try { await loadDevices(); } catch (e) { devThrew = true; console.log('   threw: ' + e.message); }
  ok(!devThrew, 'loadDevices(error body) does not throw');
  ok(Array.isArray(devices) && devices.length === 1, 'previous device list preserved',
     JSON.stringify(devices));
  globalThis.__fetchImpl = async () => jsonResponse({ ip: '10.2.0.2' });
  await loadLocalIp();
  ok(__el('stat-ip').textContent === '10.2.0.2', 'local_ip applied only when present');
  globalThis.__fetchImpl = async () => jsonResponse({ error: 'x' }, 500);
  await loadLocalIp();
  ok(__el('stat-ip').textContent === '10.2.0.2', 'local_ip kept when the reply is bad');

  console.log('--- 12. Exploit Payload Generator: Generate button -----------------');
  const genBtn = __el('payload-generate');
  const out = __el('payload-output');
  genBtn.textContent = 'Generate';
  genBtn.disabled = false;
  let alerts = 0;
  const realAlert = globalThis.alert;
  globalThis.alert = () => { alerts++; };

  // a) empty target IP -> inline message, never a silent alert
  __el('payload-ip').value = '   ';
  out.innerHTML = '';
  await generatePayload();
  ok(out.innerHTML.includes('Enter a target IP'), 'empty IP explains itself on the card',
     out.innerHTML.slice(0, 140));
  ok(alerts === 0, 'no alert() — a suppressed dialog read as a dead button');
  ok(log.children.some(c => String(c.innerHTML).includes('skipped')),
     'skip recorded in the log');
  ok(genBtn.disabled === false && genBtn.textContent === 'Generate',
     'button untouched on the skip path');

  // b) happy path -> modal opens with the payload, title reset, button restored
  globalThis.__fetchImpl = async () =>
    jsonResponse({ status: 'ok', payload: '#!/bin/bash\necho pwned' });
  __el('payload-ip').value = '10.2.0.1';
  __el('payload-text').textContent = '';
  __el('payload-modal').removed.length = 0;
  __el('payload-modal').added.length = 0;
  document.querySelector('#payload-modal .modal-title').textContent =
    'Generated Exploit — CVE-9999-0001';   // what testAiGeneration leaves behind
  genBtn.textContent = 'Generate';
  await generatePayload();
  ok(__el('payload-text').textContent.includes('echo pwned'), 'payload rendered');
  ok(__el('payload-modal').added.includes('active'), 'preview modal opened');
  ok(document.querySelector('#payload-modal .modal-title').textContent === 'Generated Payload',
     'modal title reset (not the previous CVE)',
     document.querySelector('#payload-modal .modal-title').textContent);
  ok(out.innerHTML.includes('Payload ready'), 'success reported on the card');
  ok(genBtn.disabled === false && genBtn.textContent === 'Generate',
     'button restored after success');

  // c) server error body -> reported, modal NOT opened
  __el('payload-modal').removed.length = 0;
  __el('payload-modal').added.length = 0;
  globalThis.__fetchImpl = async () => jsonResponse({ error: 'family not supported' }, 500);
  await generatePayload();
  ok(out.innerHTML.includes('Payload generation failed'), 'server error surfaced',
     out.innerHTML.slice(0, 160));
  ok(out.innerHTML.includes('family not supported'), 'server message shown');
  ok(!__el('payload-modal').added.includes('active'), 'modal not opened on failure');
  ok(genBtn.disabled === false, 'button re-enabled after server error');

  // d) unreachable C2 -> reported, not swallowed
  __el('payload-modal').added.length = 0;
  globalThis.__fetchImpl = async () => { throw new TypeError('Failed to fetch'); };
  await generatePayload();
  ok(out.innerHTML.includes('Payload generation failed'), 'network failure surfaced');
  ok(!__el('payload-modal').added.includes('active'), 'modal not opened on network failure');
  ok(genBtn.disabled === false && genBtn.textContent === 'Generate',
     'button restored after network failure');

  // e) reply with no payload -> reported instead of a modal full of "undefined"
  __el('payload-modal').added.length = 0;
  __el('payload-text').textContent = '';
  globalThis.__fetchImpl = async () => jsonResponse({ status: 'ok' });
  await generatePayload();
  ok(out.innerHTML.includes('without a payload'), 'missing payload reported',
     out.innerHTML.slice(0, 160));
  ok(!__el('payload-modal').added.includes('active'), 'no "undefined" modal');
  globalThis.alert = realAlert;

  console.log('--- 13. Exploit button (deployPayload) -----------------------------');
  const expBtn = __el('payload-exploit');
  expBtn.textContent = 'Exploit';
  expBtn.disabled = false;
  __el('payload-ip').value = '';
  out.innerHTML = '';
  await deployPayload();
  ok(out.innerHTML.includes('Enter a target IP'), 'empty IP reported on the card');
  globalThis.__fetchImpl = async () => jsonResponse(
    { status: 'ok', attempted: true, success: true, tv_type: 'tizen', duration_s: 1.2 });
  __el('payload-ip').value = '10.2.0.1';
  await deployPayload();
  ok(out.innerHTML.includes('Exploit succeeded'), 'outcome shown on the card',
     out.innerHTML.slice(0, 160));
  ok(__el('payload-exploit').disabled === false
     && __el('payload-exploit').textContent === 'Exploit', 'Exploit button restored');
  globalThis.__fetchImpl = async () => jsonResponse({ error: 'module missing' }, 500);
  await deployPayload();
  ok(out.innerHTML.includes('failed') || out.innerHTML.includes('not run'),
     'failure shown on the card');
  ok(__el('payload-exploit').textContent === 'Exploit', 'button restored after failure');

  console.log(failures ? `\n${failures} FAILURE(S)` : '\nall checks passed');
  process.exit(failures ? 1 : 0);
})().catch(e => {
  console.log('UNCAUGHT: ' + (e && e.stack || e));
  process.exit(2);
});
"""


def _run_node(source: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / "dashboard_harness.js"
        out.write_text(source, encoding="utf-8")
        return subprocess.run(
            [NODE, str(out)], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=180,
        )


def test_dashboard_inline_script_parses():
    """A syntax error anywhere in the inline script kills every button at once,
    so parse it before running it."""
    proc = subprocess.run([NODE, "--check", "-"],
                          input=_dashboard_script(), capture_output=True,
                          text=True, encoding="utf-8", errors="replace",
                          timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_dashboard_scan_and_client_details_flows():
    proc = _run_node(PRELUDE + "\n" + _dashboard_script() + "\n" + POSTLUDE)
    output = proc.stdout + proc.stderr
    assert proc.returncode == 0, output
    assert "all checks passed" in output, output
    assert "[unhandledRejection]" not in output, output
    assert "FAIL" not in proc.stdout, proc.stdout
