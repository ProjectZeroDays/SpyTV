const { chromium } = require('playwright-core');
const path = require('path');
const fs = require('fs');

(async () => {
  const outDir = path.join(__dirname, 'docs', 'screenshots');
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch({ channel: 'chrome' });
  const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1.5 });
  const page = await ctx.newPage();
  const base = 'http://127.0.0.1:9443';

  const failed = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') failed.push('console.error: ' + msg.text());
  });
  page.on('requestfailed', (req) => {
    failed.push('reqfail ' + req.method() + ' ' + req.url() + ' :: ' + (req.failure() && req.failure().errorText));
  });
  page.on('response', (res) => {
    if (res.status() >= 400) failed.push('HTTP ' + res.status() + ' ' + res.url());
  });

  await page.goto(base + '/', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(6000);

  const stat_ip = await page.$eval('#stat-ip', el => el.textContent).catch(() => null);
  const stat_devices = await page.$eval('#stat-devices', el => el.textContent).catch(() => null);
  const stat_cves = await page.$eval('#stat-cves', el => el.textContent).catch(() => null);
  const stat_clips = await page.$eval('#stat-clips', el => el.textContent).catch(() => null);
  console.log('stat-ip:    ' + JSON.stringify(stat_ip));
  console.log('stat-dev:   ' + JSON.stringify(stat_devices));
  console.log('stat-cves:  ' + JSON.stringify(stat_cves));
  console.log('stat-clips: ' + JSON.stringify(stat_clips));

  // server tab
  try {
    await page.evaluate(() => switchTab('server'));
    await page.waitForTimeout(2000);
    const srv_ip = await page.$eval('#srv-ipv4', el => el.textContent).catch(() => null);
    const srv_hostname = await page.$eval('#srv-hostname', el => el.textContent).catch(() => null);
    console.log('srv-ipv4:   ' + JSON.stringify(srv_ip));
    console.log('srv-host:   ' + JSON.stringify(srv_hostname));
    await page.screenshot({ path: path.join(outDir, 'debug-server-tab.png') });
    console.log('saved debug-server-tab.png');
  } catch (e) {
    console.log('server tab nav failed: ' + e.message.split('\n')[0]);
  }

  // top of dashboard (header)
  try {
    await page.evaluate(() => switchTab('devices'));
    await page.waitForTimeout(1500);
    await page.screenshot({ path: path.join(outDir, 'debug-devices-tab.png'), clip: { x: 0, y: 0, width: 1600, height: 400 } });
    console.log('saved debug-devices-tab.png (header crop)');
  } catch (e) {
    console.log('devices tab screenshot failed');
  }

  console.log('\n--- FAILURES ---');
  if (failed.length === 0) console.log('(none)');
  else failed.slice(0, 20).forEach(f => console.log(f));

  await browser.close();
  console.log('DONE');
})().catch((e) => { console.error('ERR', e.message); process.exit(1); });
