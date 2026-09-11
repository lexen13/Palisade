#!/usr/bin/env node
/*
 * Palisade headless regression harness  (node v24, no external packages)
 * ----------------------------------------------------------------------
 * Drives /usr/bin/chromium over the DevTools protocol using node's built-in
 * global WebSocket + fetch (both present in node 24 -- no `ws`, no puppeteer).
 *
 * What it proves, against the REAL unmodified palisade.html:
 *   1. the page loads with ZERO uncaught errors and ZERO CSP violations
 *   2. loadDemoData() populates the in-memory state and every key DOM node
 *   3. every tab can be activated without throwing
 *   4. the report-preview <iframe srcdoc> builds
 *
 * Usage:
 *   node harness.mjs <fileOrHttpUrl> <outDir> [--keep]
 * Example (file://, the real deployment origin):
 *   node harness.mjs "file://$PWD/palisade.html" ./out-file
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const TARGET_URL = process.argv[2];
const OUT_DIR    = path.resolve(process.argv[3] || '.');
const KEEP       = process.argv.includes('--keep');
const EXTRA_FLAGS = process.argv.slice(2).filter(a => a.startsWith('--chrome:')).map(a => a.slice('--chrome:'.length));
if (!TARGET_URL) { console.error('usage: node harness.mjs <url> <outDir> [--chrome:<flag>]'); process.exit(2); }
fs.mkdirSync(OUT_DIR, { recursive: true });

// Default is the Kali path this was written against. CI (and any other box that
// puts the browser elsewhere) overrides it with CHROMIUM=/path/to/chromium.
// Unset, the behaviour is byte-identical to before.
const CHROMIUM = process.env.CHROMIUM || '/usr/bin/chromium';
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ------------------------------------------------------------------ *
 * minimal CDP client over the global WebSocket (flatten/sessionId)   *
 * ------------------------------------------------------------------ */
class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.id = 0;
    this.pending = new Map();
    this.listeners = [];
    this.ready = new Promise((res, rej) => {
      this.ws.addEventListener('open', () => res());
      this.ws.addEventListener('error', e => rej(new Error('ws error: ' + (e.message || e.type))));
    });
    this.ws.addEventListener('message', ev => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { res, rej } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? rej(new Error(msg.method + ': ' + JSON.stringify(msg.error))) : res(msg.result);
      } else if (msg.method) {
        for (const l of this.listeners) l(msg.method, msg.params, msg.sessionId);
      }
    });
  }
  on(fn) { this.listeners.push(fn); }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((res, rej) => {
      this.pending.set(id, { res, rej });
      this.ws.send(JSON.stringify(payload));
    });
  }
  close() { try { this.ws.close(); } catch {} }
}

/* the bootstrap installed BEFORE any page script runs, so it captures
 * load-time exceptions and CSP violations that fire during initial parse. */
const BOOTSTRAP = `
  window.__errors = [];
  window.__csp = [];
  window.addEventListener('error', e => __errors.push(
    (e.message||'error') + (e.filename? ' @'+e.filename+':'+e.lineno : '')));
  window.addEventListener('unhandledrejection', e =>
    __errors.push('unhandledrejection: ' + (e.reason && e.reason.message || e.reason)));
  document.addEventListener('securitypolicyviolation', e => __csp.push({
    directive: e.effectiveDirective || e.violatedDirective,
    blockedURI: e.blockedURI, line: e.lineNumber, sample: e.sample }));
`;

/* the assertion probe, evaluated after demo load */
const PROBE = `(function(){
  const idlist = ["ppsmTable","stigTable","swTable","assetTable",
    "statCards","vulnCards","intelCards","assetCards","swCards","eolCards","scCards",
    "shCards","accCards","trendCards","rptCards",
    "vulnBody","intelBody","accBody","shBody","scBody","reconBody","deltaBody",
    "readyBody","eolBody","controlsBody","settingsGrid","boundaryGrid"];
  const ids = {};
  for (const id of idlist){
    const el = document.getElementById(id);
    ids[id] = el ? { present:true, rows: el.querySelectorAll('tr').length,
                     children: el.children.length, textLen:(el.textContent||'').trim().length }
                 : { present:false };
  }
  const St = (typeof S!=='undefined') ? S : (window.S||{});   // S is a top-level 'let', not window.S
  return JSON.stringify({
    hosts: Object.keys(St.hosts||{}).length,
    filesLoaded: (St.filesLoaded||[]).map(f=>({name:f.name,type:f.type,hosts:f.hosts})),
    intelRows: Object.keys((St.intel&&St.intel.rows)||{}).length,
    listingFiles: ((St.listings&&St.listings.files)||[]).length,
    meterPct: (document.getElementById('meterPct')||{}).textContent,
    meterSub: (document.getElementById('meterSub')||{}).textContent,
    tableRows: {
      ppsm: document.querySelectorAll('#ppsmTable tr').length,
      stig: document.querySelectorAll('#stigTable tr').length,
      sw:   document.querySelectorAll('#swTable tr').length,
      asset:document.querySelectorAll('#assetTable tr').length
    },
    ids
  }, null, 2);
})()`;

/* walk every nav tab, activate it, report per-tab error count + iframe srcdoc */
const TABWALK = `(function(){
  const before = __errors.length;
  const btns = [...document.querySelectorAll('#tabs button')];
  const seen = [];
  for (const b of btns){
    const n0 = __errors.length;
    b.click();
    const pane = document.querySelector('.tabpane.active');
    seen.push({ tab: b.dataset.t, active: pane? pane.id : null, newErrors: __errors.length - n0 });
  }
  return JSON.stringify(seen, null, 2);
})()`;

const REPORTPROBE = `(function(){
  // activate reports tab, wait handled by caller; report srcdoc length
  const f = document.getElementById('rptPreview');
  return JSON.stringify({
    hasIframe: !!f,
    srcdocLen: f && f.srcdoc ? f.srcdoc.length : 0,
    note: (document.getElementById('rptPreviewNote')||{}).textContent || ''
  });
})()`;

async function main() {
  const udir = fs.mkdtempSync(path.join(os.tmpdir(), 'pal-cdp-'));
  const flags = [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
    '--remote-allow-origins=*',
    '--remote-debugging-port=0',
    '--window-size=1440,1800',
    `--user-data-dir=${udir}`,
    ...EXTRA_FLAGS,
    'about:blank',
  ];
  const chrome = spawn(CHROMIUM, flags, { stdio: ['ignore', 'ignore', 'pipe'] });
  let stderr = '';
  chrome.stderr.on('data', d => { stderr += d; });

  // wait for the DevToolsActivePort file
  const portFile = path.join(udir, 'DevToolsActivePort');
  let port = null;
  for (let i = 0; i < 100; i++) {
    if (fs.existsSync(portFile)) {
      const line = fs.readFileSync(portFile, 'utf8').split('\n')[0].trim();
      if (line) { port = line; break; }
    }
    await sleep(100);
  }
  if (!port) { chrome.kill('SIGKILL'); throw new Error('chromium never opened a debug port.\nstderr:\n' + stderr); }

  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const cdp = new CDP(version.webSocketDebuggerUrl);
  await cdp.ready;

  const console_ = [];
  const cdpErrors = [];
  const logEntries = [];

  // browser-level: create a page target and attach (flatten)
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const S = (m, p) => cdp.send(m, p, sessionId);

  cdp.on((method, params, sid) => {
    if (sid !== sessionId) return;
    if (method === 'Runtime.consoleAPICalled') {
      console_.push({ type: params.type, text: params.args.map(a => a.value ?? a.description ?? a.unserializableValue ?? JSON.stringify(a.preview?.properties?.map(x=>x.value) ?? '')).join(' ') });
    } else if (method === 'Runtime.exceptionThrown') {
      const d = params.exceptionDetails;
      cdpErrors.push((d.exception && (d.exception.description || d.exception.value)) || d.text);
    } else if (method === 'Log.entryAdded') {
      const e = params.entry;
      logEntries.push({ source: e.source, level: e.level, text: e.text, url: e.url });
    }
  });

  await S('Page.enable');
  await S('Runtime.enable');
  await S('Log.enable');
  // headless=new ignores --window-size for the layout viewport; force a real
  // desktop viewport so the nav rail renders and the screenshot is diffable.
  await S('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1800, deviceScaleFactor: 1, mobile: false });
  await S('Page.addScriptToEvaluateOnNewDocument', { source: BOOTSTRAP });
  // auto-dismiss any native dialog so the run never blocks
  cdp.on(async (method, params, sid) => {
    if (sid === sessionId && method === 'Page.javascriptDialogOpening') {
      try { await S('Page.handleJavaScriptDialog', { accept: true }); } catch {}
    }
  });

  // navigate to the real target (bootstrap runs first on this fresh document)
  const loaded = new Promise(res => {
    cdp.on((method, params, sid) => { if (sid === sessionId && method === 'Page.loadEventFired') res(); });
  });
  await S('Page.navigate', { url: TARGET_URL });
  await Promise.race([loaded, sleep(8000)]);
  await sleep(400); // let the first-run wizard setTimeout(90) + any microtasks settle

  const evalx = async expr => (await S('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true })).result.value;

  // phase 1: load demo data by CLICKING the real "Load demo data" button -- NOT by
  // calling the function. This makes the harness a true gate for a strict CSP: if the
  // button's handler does not run, hosts stays 0 and inlineHandlerFired fails loudly.
  //
  // Block C4 converted the static body from inline onclick="loadDemoData()" to the
  // delegated data-click="loadDemoData" form, so the button is located by EITHER
  // attribute. The assertion is unchanged in strength -- still a real .click() on the
  // real control, with the verdict resting on whether data actually loaded -- and on a
  // converted build it now additionally proves the document-level dispatcher works.
  const clickRet = await evalx(`(function(){
    var all=[...document.querySelectorAll('button[onclick],button[data-click]')];
    var b=all.find(x=>/loadDemoData/.test(x.getAttribute('onclick')||''));
    if(b){ b.click(); return 'clicked:onclick'; }
    b=all.find(x=>x.getAttribute('data-click')==='loadDemoData');
    if(b){ b.click(); return 'clicked:data-click'; }
    return 'no-button';
  })()`);
  await sleep(500); // renderAll + any debounced timers
  let probe = JSON.parse(await evalx(PROBE));
  const inlineHandlerFired = probe.hosts > 0;

  // fallback so later phases still have data to assert on even when inline
  // handlers are (perhaps intentionally) disabled -- but the verdict above stands.
  let demoErr = null;
  if (!inlineHandlerFired) {
    const demoRet = await S('Runtime.evaluate', { expression: 'typeof loadDemoData==="function" ? (loadDemoData(),"called") : "missing"', returnByValue: true });
    demoErr = demoRet.exceptionDetails ? (demoRet.exceptionDetails.exception?.description || demoRet.exceptionDetails.text) : null;
    await sleep(500);
  }

  // phase 2: assertions
  probe = JSON.parse(await evalx(PROBE));

  // phase 3: walk all tabs
  const tabwalk = JSON.parse(await evalx(TABWALK));

  // phase 4: reports tab -> iframe srcdoc (needs the 220ms rptTouch debounce)
  await evalx(`[...document.querySelectorAll('#tabs button')].find(b=>b.dataset.t==='reports').click(); 'ok'`);
  await sleep(700);
  const report = JSON.parse(await evalx(REPORTPROBE));

  // phase 4b: GENERATED inline-handler canary. The onclick at line ~4920 is
  // produced inside a JS template literal fed to innerHTML -- a distinct case
  // from the static-HTML handler, and the one the app relies on most. Clicking
  // it must open the boundary modal; under a strict CSP the handler never fires.
  //
  // Block C5 converted the renderers from onclick="openBoundaries('k')" to the delegated
  // data-click="openBoundaries" data-arg="k" form, so the button is located by EITHER
  // attribute. The assertion is unchanged in strength -- still a real .click() on the real
  // generated control, with the verdict resting on whether the boundary modal actually
  // opened -- and on a converted build it additionally proves that a renderer-produced
  // data-key/data-arg survives the round trip through the document-level dispatcher.
  const genHandler = await evalx(`(function(){
    var all=[...document.querySelectorAll('#ppsmTable button[onclick],#ppsmTable button[data-click]')];
    var b=all.find(x=>/openBoundaries/.test(x.getAttribute('onclick')||''))
         || all.find(x=>x.getAttribute('data-click')==='openBoundaries');
    if(!b) return {found:false, opened:false};
    b.click();
    var m=document.getElementById('bModal');
    var opened = !!(m && getComputedStyle(m).display!=='none');
    if(opened && typeof closeModal==='function'){ try{closeModal();}catch(e){} }
    return {found:true, opened:opened};
  })()`);
  const generatedHandlerFired = genHandler.found && genHandler.opened;

  // collect the in-page error / csp arrays
  const pageErrors = await evalx('JSON.stringify(window.__errors||[])').then(JSON.parse).catch(() => []);
  const pageCsp    = await evalx('JSON.stringify(window.__csp||[])').then(JSON.parse).catch(() => []);

  // screenshot (back to overview for a stable shot)
  await evalx(`[...document.querySelectorAll('#tabs button')].find(b=>b.dataset.t==='overview').click(); 'ok'`);
  await sleep(200);
  const shot = await S('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  fs.writeFileSync(path.join(OUT_DIR, 'screenshot.png'), Buffer.from(shot.data, 'base64'));

  // dump the fully-rendered DOM for diffing
  const dom = await evalx('document.documentElement.outerHTML');
  fs.writeFileSync(path.join(OUT_DIR, 'dom-after-demo.html'), dom);

  const result = {
    meta: { url: TARGET_URL, when: new Date().toISOString(), chromium: version.Browser, port, flags: EXTRA_FLAGS },
    demoTrigger: clickRet,
    inlineHandlerFired,
    generatedHandler: genHandler,
    generatedHandlerFired,
    demoLoadError: demoErr,
    consoleErrors: console_.filter(c => c.type === 'error' || c.type === 'assert'),
    consoleWarnings: console_.filter(c => c.type === 'warning'),
    consoleAll: console_,
    cdpExceptions: cdpErrors,
    logEntries,
    pageErrors,
    cspViolations: pageCsp,
    probe,
    tabwalk,
    report,
    verdict: {}
  };

  // PASS/FAIL rollup
  const totalErrors = cdpErrors.length + pageErrors.length + result.consoleErrors.length;
  const tabErrors = tabwalk.reduce((n, t) => n + t.newErrors, 0);
  result.verdict = {
    zeroErrors: totalErrors === 0 && demoErr === null,
    zeroCsp: pageCsp.length === 0,
    inlineHandlerFired,                       // static onclick="loadDemoData()" actually loaded data
    generatedHandlerFired,                    // innerHTML-generated onclick="openBoundaries()" actually fired
    hosts6: probe.hosts === 6,
    coreTablesPopulated: probe.tableRows.ppsm > 1 && probe.tableRows.stig > 1 &&
                         probe.tableRows.sw > 1 && probe.tableRows.asset > 1,
    meterComputed: probe.meterPct && probe.meterPct !== '–' && probe.meterPct !== '',
    allTabsClean: tabErrors === 0,
    reportBuilt: report.srcdocLen > 200,
  };
  result.verdict.PASS = Object.values(result.verdict).every(Boolean);

  fs.writeFileSync(path.join(OUT_DIR, 'result.json'), JSON.stringify(result, null, 2));

  // a compact human summary
  const populated = Object.entries(probe.ids)
    .filter(([, v]) => v.present && (v.rows > 1 || v.children > 0 || v.textLen > 0))
    .map(([k, v]) => `${k}  rows=${v.rows} children=${v.children} textLen=${v.textLen}`);
  const summary =
`PALISADE BASELINE  ${result.meta.when}
url:      ${TARGET_URL}
chromium: ${version.Browser}
extraFlags: ${EXTRA_FLAGS.join(' ') || '(none)'}

VERDICT: ${result.verdict.PASS ? 'PASS' : 'FAIL'}
${Object.entries(result.verdict).map(([k, v]) => `  ${v ? 'ok ' : 'XX '} ${k}`).join('\n')}

demoTrigger: clicked the real "Load demo data" button -> ${clickRet}; inlineHandlerFired=${inlineHandlerFired}
generatedHandler: clicked the innerHTML-generated openBoundaries control (onclick= or data-click=) -> found=${genHandler.found} opened=${genHandler.opened}
demoLoadError: ${demoErr || 'none'}
hosts: ${probe.hosts}   intelRows: ${probe.intelRows}   listingFiles: ${probe.listingFiles}
meter: ${probe.meterPct} (${probe.meterSub})
core table <tr> counts: ppsm=${probe.tableRows.ppsm} stig=${probe.tableRows.stig} sw=${probe.tableRows.sw} asset=${probe.tableRows.asset}
report iframe srcdoc length: ${report.srcdocLen}  note="${report.note}"

console errors: ${result.consoleErrors.length}
cdp exceptions: ${cdpErrors.length}
page window.onerror: ${pageErrors.length}
CSP violations: ${pageCsp.length}
${pageErrors.length ? '\nPAGE ERRORS:\n' + pageErrors.map(e => '  - ' + e).join('\n') : ''}${cdpErrors.length ? '\nCDP EXCEPTIONS:\n' + cdpErrors.map(e => '  - ' + e).join('\n') : ''}${pageCsp.length ? '\nCSP:\n' + pageCsp.map(c => '  - ' + JSON.stringify(c)).join('\n') : ''}

tab walk (newErrors per tab):
${tabwalk.map(t => `  ${t.tab.padEnd(16)} -> ${t.active}  err+${t.newErrors}`).join('\n')}

populated containers (${populated.length}):
${populated.map(s => '  ' + s).join('\n')}
`;
  fs.writeFileSync(path.join(OUT_DIR, 'summary.txt'), summary);
  process.stdout.write(summary);

  cdp.close();
  chrome.kill('SIGKILL');
  if (!KEEP) try { fs.rmSync(udir, { recursive: true, force: true }); } catch {}
  process.exit(result.verdict.PASS ? 0 : 1);
}

main().catch(err => { console.error('HARNESS ERROR:', err.stack || err); process.exit(3); });
