//Smoke test of the web page in a real browser, over the Chrome DevTools protocol: runs the demo (#demo), checks that the
//report opens full screen only when asked, renders the history trend column, and reports console errors and CSP violations.
//  node page-check.mjs <chrome or edge executable> <page url> <screenshot folder> [width]
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const [browser, url, shots, widthArg] = process.argv.slice(2);
const width = Number(widthArg ?? 1280);
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'azcmply-page-'));
const port = 9300 + Math.floor(Math.random() * 500);
const chrome = spawn(browser, ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check', `--user-data-dir=${profile}`,
    `--remote-debugging-port=${port}`, `--window-size=${width},1000`, 'about:blank'], { stdio: 'ignore' });

const sleep = ms => new Promise(r => setTimeout(r, ms));
let target;
for (let i = 0; i < 50 && !target; i++) {
    await sleep(200);
    try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find(t => t.type === 'page'); } catch { /* not up yet */ }
}
if (!target) { console.log('FAIL browser did not start'); chrome.kill(); process.exit(2); }

const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r));
let nextId = 1;
const waiting = new Map();
const problems = [];
ws.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id && waiting.has(message.id)) { waiting.get(message.id)(message); waiting.delete(message.id); return; }
    if (message.method === 'Runtime.exceptionThrown') { problems.push(`exception: ${message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text}`); }
    if (message.method === 'Runtime.consoleAPICalled' && ['error', 'warning'].includes(message.params.type)) { problems.push(`console ${message.params.type}: ${message.params.args.map(a => a.value ?? a.description).join(' ')}`); }
    if (message.method === 'Log.entryAdded' && ['error', 'warning'].includes(message.params.entry.level)) { problems.push(`log ${message.params.entry.level}: ${message.params.entry.text} ${message.params.entry.url ?? ''}`); }
});
function send(method, params = {}) {
    return new Promise(resolve => { const id = nextId++; waiting.set(id, resolve); ws.send(JSON.stringify({ id, method, params })); });
}
async function evaluate(expression) {
    const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    return r.result?.result?.value;
}
async function screenshot(name) {
    const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    fs.writeFileSync(path.join(shots, name), Buffer.from(r.result.data, 'base64'));
}

fs.mkdirSync(shots, { recursive: true });
await send('Runtime.enable');
await send('Log.enable');
await send('Page.enable');
await send('Emulation.setDeviceMetricsOverride', { width, height: 1000, deviceScaleFactor: 1, mobile: width < 600 });
await send('Page.navigate', { url });
const started = Date.now();
let state = '';
while (Date.now() - started < 120000) {
    await sleep(500);
    state = await evaluate(`document.querySelector('#progress-title')?.textContent + '|' + !document.querySelector('#result').hidden + '|' + !document.querySelector('#view-report').disabled`);
    if (/^Stopped\|/.test(state ?? '') || /^Done\|true\|true/.test(state ?? '')) { break; }
}
await sleep(1000);
const checks = [];
const check = (name, ok) => { checks.push(`${ok ? 'PASS' : 'FAIL'}  ${name}`); return ok; };
check('the demo analysis completes and the report is ready', /^Done\|true\|true/.test(state ?? ''));
check('the report is not shown until asked for', await evaluate(`document.querySelector('#viewer').hidden`));
const buildExpression = `new URL(document.querySelector('script[src*="js/boot.js"]').src).searchParams.get('v')`;
check('the page runs the stamped build', await evaluate(`localStorage.getItem('azcmply.build') === ${buildExpression} && !!${buildExpression}`));
const summary = await evaluate(`[...document.querySelectorAll('#summary .kpi')].map(k => k.innerText.replace(/\\n/g, ' ')).join(' | ')`);
const banner = await evaluate(`document.querySelector('#banner').hidden ? '' : document.querySelector('#banner').innerText`);
check('no horizontal overflow', !(await evaluate(`document.documentElement.scrollWidth > window.innerWidth + 1`)));
await evaluate(`window.scrollTo({ top: 0, behavior: 'instant' })`);
await sleep(400);
await screenshot(`page-${width}.png`);
await evaluate(`document.querySelector('#result').scrollIntoView({ behavior: 'instant' })`);
await sleep(400);
await screenshot(`result-${width}.png`);

//the preview opens the report full screen; Escape closes it again
await evaluate(`document.querySelector('#preview').click()`);
await sleep(2500);
check('the preview opens the report full screen', await evaluate(`!document.querySelector('#viewer').hidden && document.body.classList.contains('viewer-open')`));
await screenshot(`viewer-${width}.png`);
await evaluate(`document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))`);
await sleep(300);
check('Escape closes the report', await evaluate(`document.querySelector('#viewer').hidden`));
await evaluate(`document.querySelector('#view-report').click()`);
await sleep(800);
check('the button opens the report full screen', await evaluate(`!document.querySelector('#viewer').hidden`));
await evaluate(`document.querySelector('#viewer-close').click()`);

//history: three runs of one subscription going up, two of another going down, one on its own
await evaluate(`(async () => {
    const store = await import('./js/store.js');
    await store.clearAnalyses();
    const run = (sub, name, day, score) => JSON.stringify({
        schemaVersion: 2, analyzer: { version: '1.0.0', tests: 245 },
        ingest: { folder: sub + day, subscriptionId: sub, subscriptionName: name, tenantId: 't', startedAt: '2026-09-' + day + 'T08:00:00Z' },
        analyzedAt: '2026-09-' + day + 'T08:05:00Z',
        summary: { postureScore: score, tests: { Pass: 100, Fail: 50, Unknown: 5, NotApplicable: 90, Error: 0 } }, tests: []
    });
    for (const [sub, name, day, score] of [['aaaa', 'Production', '02', 41.5], ['aaaa', 'Production', '09', 55.2], ['aaaa', 'Production', '16', 63],
        ['bbbb', 'Development', '03', 72.4], ['bbbb', 'Development', '10', 64.1], ['cccc', 'Sandbox', '12', 80]]) {
        await store.saveAnalysis(run(sub, name, day, score), 'test');
    }
})()`);
//a browser that last ran another build refetches the page's files and records the new build
await evaluate(`localStorage.setItem('azcmply.build', 'older-build')`);
await send('Page.navigate', { url: url.replace(/#.*$/, '') + '?history#history' });
await sleep(3000);
check('a new build is refetched past the browser cache', await evaluate(`localStorage.getItem('azcmply.build') === ${buildExpression} && document.querySelector('#version').textContent.startsWith('v')`));
const trends = await evaluate(`[...document.querySelectorAll('#history-rows tr')].map(r => (r.querySelector('.trend')?.className ?? 'none') + ' ' + (r.querySelector('.trend')?.innerText ?? '').trim()).join(' | ')`);
check('history shows up and down trends per subscription', /trend up.*\+21\.5/.test(trends) && /trend down.*-8\.3/.test(trends) && /none/.test(trends));
await evaluate(`document.querySelector('#history').scrollIntoView({ behavior: 'instant' })`);
await sleep(400);
await screenshot(`history-${width}.png`);
await evaluate(`(async () => { const store = await import('./js/store.js'); await store.clearAnalyses(); })()`);

console.log(`summary: ${summary}`);
console.log(`google analytics loaded: ${await evaluate('!!window.google_tag_manager')}`);
console.log(`history trends: ${trends}`);
if (banner) { console.log(`banner: ${banner}`); }
console.log(checks.join('\n'));
console.log(problems.length ? `problems:\n  ${problems.join('\n  ')}` : 'problems: none');
ws.close();
chrome.kill();
try { fs.rmSync(profile, { recursive: true, force: true }); } catch { /* chrome may still hold files */ }
process.exitCode = checks.every(c => c.startsWith('PASS')) && !problems.length && !banner ? 0 : 1;
