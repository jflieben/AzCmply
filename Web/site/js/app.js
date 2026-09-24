//The page: sign-in, choosing what to assess, progress, the report and the history in this browser.
//The work itself runs in worker.js; this file only talks to it and to the user.
import config from './config.js';
import * as auth from './auth.js';
import * as store from './store.js';
import plan from '../generated/ingest-plan.js';

const $ = selector => document.querySelector(selector);
const SETTINGS_KEY = 'azcmply.settings';
const PREFERENCES_KEY = 'azcmply.preferences';
const THEME_KEY = 'azcmply.theme';
const GUID = /^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$/i;

//#region small helpers

function readStorage(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key) ?? 'null') ?? fallback; } catch { return fallback; }
}
function writeStorage(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage blocked: settings last for this visit */ }
}

function element(tag, props = {}, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null) { continue; }
        if (key === 'class') { el.className = value; }
        else if (key === 'text') { el.textContent = value; }
        else if (key.startsWith('on')) { el.addEventListener(key.slice(2), value); }
        else { el.setAttribute(key, value); }
    }
    for (const child of children) { if (child !== null && child !== undefined) { el.append(child); } }
    return el;
}

function formatDate(iso) {
    const d = new Date(iso);
    return Number.isNaN(d.getTime()) ? (iso ?? '') : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function download(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = element('a', { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
}

function safeName(text) { return String(text ?? 'azcmply').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 80) || 'azcmply'; }

function showBanner(kind, lines, link) {
    const banner = $('#banner');
    banner.replaceChildren(...lines.map(line => element('p', { text: line })));
    if (link) { banner.append(element('p', {}, element('a', { href: link.href, target: '_blank', rel: 'noopener noreferrer', text: link.text }))); }
    banner.className = `banner ${kind}`;
    banner.hidden = false;
    banner.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}
function hideBanner() { $('#banner').hidden = true; }

//#endregion

//#region worker

const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
const pending = new Map();
let nextId = 1;
let workerReady;
const ready = new Promise(resolve => { workerReady = resolve; });

worker.onmessage = async event => {
    const message = event.data;
    switch (message.type) {
        case 'ready': workerReady(); break;
        case 'log': appendLog(message.text); break;
        case 'progress': onProgress(message); break;
        case 'token':
            try { worker.postMessage({ type: 'token', rid: message.rid, token: await auth.getToken(message.resource) }); }
            catch (e) { worker.postMessage({ type: 'token', rid: message.rid, error: e.message }); }
            break;
        case 'result': {
            const request = pending.get(message.id);
            pending.delete(message.id);
            if (!request) { break; }
            if (message.ok) { request.resolve(message.value); }
            else { const error = new Error(message.error); error.cancelled = message.cancelled; request.reject(error); }
            break;
        }
        default: break;
    }
};
worker.onerror = event => showBanner('error', ['The page could not start its background worker.', event.message ?? '']);

async function call(op, payload = {}) {
    await ready;
    return new Promise((resolve, reject) => {
        const id = nextId++;
        pending.set(id, { resolve, reject });
        worker.postMessage({ op, id, ...payload });
    });
}

//#endregion

//#region settings, theme and account

function loadSettings() {
    const saved = readStorage(SETTINGS_KEY, {});
    return {
        clientId: saved.clientId || config.jsolveClientId || '',
        tenant: saved.tenant || config.defaultTenant,
        cloud: saved.cloud || config.defaultCloud,
        own: !!saved.clientId
    };
}

function renderSettings() {
    const s = loadSettings();
    $('#set-client').value = s.own ? s.clientId : '';
    $('#set-client').placeholder = config.jsolveClientId ? `${config.jsolveClientId} (JSolve app)` : '00000000-0000-0000-0000-000000000000';
    $('#set-tenant').value = s.tenant === config.defaultTenant ? '' : s.tenant;
    $('#set-cloud').value = s.cloud;
    $('#redirect-uri').textContent = auth.redirectUri();
    $('#reset-settings').hidden = !config.jsolveClientId;
    $('#consent-link').hidden = !s.clientId;
    if (s.clientId) { $('#consent-link').href = auth.adminConsentUrl(s); }
    const note = $('#app-note');
    if (!s.clientId) {
        note.textContent = 'This copy of AzCmply has no app registration configured. Enter the application id of your own app registration under "App registration and tenant"; the setup guide explains how to create one in a minute.';
        $('#app-settings').open = true;
    } else if (s.own) {
        note.textContent = `Signs in with your own app registration (${s.clientId}) in ${s.tenant}.`;
    } else {
        note.textContent = 'Signs in with the AzCmply app of JSolve B.V. The first time, an administrator of your tenant grants it read access for everyone (admin consent link under "App registration and tenant").';
    }
}

function saveSettings() {
    const clientId = $('#set-client').value.trim();
    const tenant = $('#set-tenant').value.trim();
    if (clientId && !GUID.test(clientId)) { showBanner('error', ['The application id must be a GUID, as shown on the overview of the app registration.']); return; }
    writeStorage(SETTINGS_KEY, { clientId, tenant, cloud: $('#set-cloud').value });
    hideBanner();
    renderSettings();
}

const THEMES = ['auto', 'light', 'dark'];
function applyTheme(theme) {
    if (theme === 'auto') { delete document.documentElement.dataset.theme; } else { document.documentElement.dataset.theme = theme; }
    $('#theme').textContent = `Theme: ${theme === 'auto' ? 'automatic' : theme}`;
    $('#theme').dataset.theme = theme;
}

function renderAccount() {
    const account = auth.account();
    $('#signed-out').hidden = !!account;
    $('#signed-in').hidden = !account;
    $('#sign-out').hidden = !account;
    $('#account').hidden = !account;
    if (account) {
        $('#account').textContent = account.username ? `${account.name ?? ''} (${account.username})`.trim() : (account.name ?? 'Signed in');
        loadSubscriptions();
    }
}

async function loadSubscriptions() {
    const select = $('#subscription');
    select.replaceChildren(element('option', { value: '', text: 'Loading subscriptions...' }));
    try {
        const arm = plan.cloudEndpoints[auth.settings().cloud].Arm;
        const token = await auth.getToken('Arm');
        const subscriptions = [];
        let next = `${arm}/subscriptions?api-version=${plan.coreApiVersions.subscription}`;
        while (next) {
            const response = await fetch(next, { headers: { Authorization: `Bearer ${token}` } });
            const json = await response.json();
            if (!response.ok) { throw new Error(json?.error?.message ?? `HTTP ${response.status}`); }
            subscriptions.push(...(json.value ?? []));
            next = json.nextLink ?? null;
        }
        subscriptions.sort((a, b) => (a.displayName ?? '').localeCompare(b.displayName ?? ''));
        const preferred = readStorage(PREFERENCES_KEY, {}).subscriptionId;
        select.replaceChildren(...(subscriptions.length
            ? subscriptions.map(s => element('option', { value: s.subscriptionId, text: `${s.displayName} (${s.subscriptionId})${s.state && s.state !== 'Enabled' ? `, ${s.state}` : ''}` }))
            : [element('option', { value: '', text: 'No subscriptions visible to this account in this tenant' })]));
        if (preferred && subscriptions.some(s => s.subscriptionId === preferred)) { select.value = preferred; }
    } catch (e) {
        select.replaceChildren(element('option', { value: '', text: 'Could not list subscriptions' }));
        showBanner('error', ['Listing the subscriptions failed.', e.message]);
    }
}

//#endregion

//#region progress

const PHASES = {
    demo: 'Loading the demo data',
    subscription: 'Subscription settings, RBAC, policy and Defender for Cloud',
    resources: 'Resources and their settings',
    resourceGraph: 'Resource Graph tables',
    activityLog: 'Activity log',
    graph: 'Entra ID',
    analysis: 'Analysis',
    report: 'Report'
};
let phaseOrder = [];
let busy = false;

function setBusy(value) {
    busy = value;
    for (const id of ['#run', '#demo', '#sign-in', '#sign-out']) { const el = $(id); if (el) { el.disabled = value; } }
}

function startProgress(title, phases, cancellable) {
    phaseOrder = phases;
    $('#progress-title').textContent = title;
    $('#log').textContent = '';
    showIssues([], 0);
    document.querySelector('.log-view').open = false;
    $('#cancel').hidden = !cancellable;
    $('#phases').replaceChildren(...phases.map(key => element('li', { class: 'phase', 'data-phase': key },
        element('span', { class: 'icon', 'aria-hidden': 'true' }),
        element('span', { class: 'label', text: PHASES[key] }),
        element('span', { class: 'count' }),
        element('span', { class: 'bar', 'aria-hidden': 'true' }, element('i'))
    )));
    $('#progress').hidden = false;
    $('#progress').scrollIntoView({ block: 'start', behavior: 'smooth' });
}

function phaseElement(key) { return document.querySelector(`.phase[data-phase="${key}"]`); }

function setPhase(key, state, done, total) {
    const index = phaseOrder.indexOf(key);
    if (index < 0) { return; }
    if (state === 'active' || state === 'done') {
        for (const earlier of phaseOrder.slice(0, index)) {
            const el = phaseElement(earlier);
            if (el && !el.classList.contains('done') && !el.classList.contains('failed')) {
                el.classList.remove('active');
                el.classList.add('done');
                el.querySelector('.bar i').style.width = '100%';
            }
        }
    }
    const el = phaseElement(key);
    el.classList.remove('active', 'done', 'failed');
    el.classList.add(state);
    if (total) {
        el.querySelector('.count').textContent = `${done} of ${total}`;
        el.querySelector('.bar i').style.width = `${Math.round(100 * done / total)}%`;
    }
    if (state === 'done') { el.querySelector('.bar i').style.width = '100%'; }
}

function onProgress({ phase, done, total }) { setPhase(phase, done >= total ? 'done' : 'active', done, total); }

function failActivePhase() {
    const active = document.querySelector('.phase.active') ?? document.querySelector('.phase:not(.done)');
    if (active) { active.classList.remove('active'); active.classList.add('failed'); }
}

//data the collection could not read, with the reason, so an admin can act on it; the log shows every failed request
function showIssues(issues, failedRequests) {
    const box = $('#issues');
    box.hidden = !issues.length;
    $('#issue-list').replaceChildren(...issues.map(issue => element('li', {},
        element('code', { text: issue.section }), `${issue.status === 'partial' ? ' (partly read)' : ''}: ${issue.detail}`)));
    if (failedRequests) { document.querySelector('.log-view').open = true; }
}

function appendLog(text) {
    const log = $('#log');
    log.textContent += `${text}\n`;
    if (log.textContent.length > 200000) { log.textContent = log.textContent.slice(-150000); }
    log.scrollTop = log.scrollHeight;
}

//#endregion

//#region result, report and viewer

const SVG = 'http://www.w3.org/2000/svg';
let current = null;
let reportHtml = null;
let frameHtml = null;
let frameCounter = 0;
let focusBeforeViewer = null;

function svg(tag, attributes = {}, ...children) {
    const el = document.createElementNS(SVG, tag);
    for (const [key, value] of Object.entries(attributes)) { el.setAttribute(key, value); }
    for (const child of children) { if (child !== null && child !== undefined) { el.append(child); } }
    return el;
}

//rating bands of the report's posture score
function rating(score) {
    if (score === null || score === undefined) { return { label: 'No score', level: 'none' }; }
    if (score >= 85) { return { label: 'Good', level: 'good' }; }
    if (score >= 70) { return { label: 'Fair', level: 'fair' }; }
    if (score >= 50) { return { label: 'Needs improvement', level: 'weak' }; }
    return { label: 'At risk', level: 'risk' };
}

window.addEventListener('message', event => {
    const frame = $('#report-frame');
    if (event.source === frame.contentWindow && event.data?.reportFrame === 'ready' && frameHtml) {
        frame.contentWindow.postMessage({ html: frameHtml }, '*');
    }
});

function loadFrame() {
    if (frameHtml === reportHtml) { return; }
    frameHtml = reportHtml;
    frameCounter++;
    $('#report-frame').src = `report-frame.html?r=${frameCounter}`;
}

function openViewer() {
    if (!reportHtml) { return; }
    focusBeforeViewer = document.activeElement;
    $('#viewer').hidden = false;
    document.body.classList.add('viewer-open');
    loadFrame();
    $('#viewer-close').focus();
}

function closeViewer() {
    if ($('#viewer').hidden) { return; }
    $('#viewer').hidden = true;
    document.body.classList.remove('viewer-open');
    focusBeforeViewer?.focus?.();
}

function reportFileName() {
    const results = current?.results;
    return `${safeName(current?.folder ?? (results ? `${results.ingest.subscriptionId}_${results.ingest.startedAt}` : 'report'))}.html`;
}

function downloadReport() { if (reportHtml) { download(new Blob([reportHtml], { type: 'text/html' }), reportFileName()); } }

function kpi(label, value, sub) {
    return element('div', { class: 'kpi' }, element('div', { class: 'label', text: label }), element('div', { class: 'value', text: value }), sub ? element('div', { class: 'sub', text: sub }) : null);
}

//the clickable preview of the report: its cover in miniature, with the score ring
function renderPreview(results) {
    const score = results.summary.postureScore;
    const band = rating(score);
    const tests = results.summary.tests;
    const evaluated = tests.Pass + tests.Fail + tests.Unknown + tests.Error;
    const circumference = 2 * Math.PI * 26;
    const arc = score === null ? 0 : Math.max(0.5, circumference * score / 100);
    const organization = $('#rep-org').value.trim();
    const ring = svg('svg', { class: 'pv-ring', viewBox: '0 0 64 64', 'aria-hidden': 'true' },
        svg('circle', { class: 'pv-track', cx: '32', cy: '32', r: '26' }),
        svg('circle', { class: `pv-arc ${band.level}`, cx: '32', cy: '32', r: '26', 'stroke-dasharray': `${arc.toFixed(2)} ${circumference.toFixed(2)}`, transform: 'rotate(-90 32 32)' }),
        svg('text', { class: 'pv-score', x: '32', y: '37', 'text-anchor': 'middle' }, score === null ? '-' : String(score))
    );
    $('#preview').replaceChildren(
        element('span', { class: 'pv-cover' },
            element('span', { class: 'pv-eyebrow', text: ($('#rep-title').value.trim() || 'Azure security assessment').toUpperCase() }),
            element('span', { class: 'pv-title', text: organization || results.ingest.subscriptionName || results.ingest.subscriptionId }),
            element('span', { class: 'pv-meta', text: `Data collected ${formatDate(results.ingest.startedAt)}` })
        ),
        element('span', { class: 'pv-body' },
            ring,
            element('span', { class: 'pv-facts' },
                element('span', { class: 'pv-rating', text: `Posture score, ${band.label.toLowerCase()}` }),
                element('span', { class: 'pv-line', text: `${tests.Fail} of ${evaluated} evaluated tests failing` }),
                element('span', { class: 'pv-cta' },
                    svg('svg', { viewBox: '0 0 16 16', 'aria-hidden': 'true' }, svg('path', { d: 'M9.5 2.5h4v4M13.5 2.5L8.5 7.5M6.5 13.5h-4v-4M2.5 13.5l5-5' })),
                    'Open report')
            )
        )
    );
    $('#preview').setAttribute('aria-label', `Open the report of ${results.ingest.subscriptionName ?? results.ingest.subscriptionId}, posture score ${score ?? 'none'}, full screen`);
}

function setReportReady(ready, text) {
    $('#preview').disabled = !ready;
    $('#view-report').disabled = !ready;
    $('#view-report').textContent = text ?? (ready ? 'View report' : 'Preparing the report...');
    $('#viewer-download').disabled = !ready;
}

//shows an analysis: summary, downloads and a way to open its report. analysis: { resultsText, testsCsv, findingsCsv, folder, source, id }
async function showResult(analysis, { open = false } = {}) {
    const results = JSON.parse(analysis.resultsText.replace(/^\uFEFF/, ''));
    current = { ...analysis, results };
    reportHtml = null;
    closeViewer();
    const tests = results.summary.tests;
    const evaluated = tests.Pass + tests.Fail + tests.Unknown + tests.Error;
    $('#summary').replaceChildren(
        kpi('Subscription', results.ingest.subscriptionName ?? results.ingest.subscriptionId, results.ingest.subscriptionId),
        kpi('Data collected', formatDate(results.ingest.startedAt), `analyzer ${results.analyzer.version}, ${results.analyzer.tests} tests`),
        kpi('Posture score', results.summary.postureScore === null ? 'none' : `${results.summary.postureScore}`, 'out of 100'),
        kpi('Failing tests', `${tests.Fail}`, `of ${evaluated} evaluated`)
    );
    const downloads = [
        element('button', { type: 'button', class: 'btn small', text: 'Report (.html)', onclick: downloadReport }),
        element('button', { type: 'button', class: 'btn small', text: 'results.json', onclick: () => download(new Blob([analysis.resultsText], { type: 'application/json' }), 'results.json') })
    ];
    if (analysis.testsCsv) { downloads.push(element('button', { type: 'button', class: 'btn small', text: 'tests.csv', onclick: () => download(new Blob([analysis.testsCsv], { type: 'text/csv' }), 'tests.csv') })); }
    if (analysis.findingsCsv) { downloads.push(element('button', { type: 'button', class: 'btn small', text: 'findings.csv', onclick: () => download(new Blob([analysis.findingsCsv], { type: 'text/csv' }), 'findings.csv') })); }
    if (analysis.ingestFolder) {
        downloads.push(element('button', {
            type: 'button', class: 'btn small', text: 'Ingestion (.zip)', onclick: async event => {
                event.target.disabled = true;
                try { download((await call('exportIngest', { folder: analysis.ingestFolder })).blob, `${safeName(analysis.ingestFolder)}.zip`); }
                catch (e) { showBanner('error', ['The ingestion could not be packed.', e.message]); }
                finally { event.target.disabled = false; }
            }
        }));
    }
    $('#downloads').replaceChildren(...downloads);
    renderPreview(results);
    setReportReady(false);
    await fillBaselines();
    $('#result').hidden = false;
    $('#result').scrollIntoView({ block: 'start', behavior: 'smooth' });
    await renderReport();
    if (open) { openViewer(); }
}

//earlier runs of the same subscription (collected before this one), oldest first
async function earlierRuns() {
    const startedAt = Date.parse(current.results.ingest.startedAt);
    const runs = await store.analysesOf(current.results.ingest.subscriptionId);
    return runs.filter(r => r.id !== current.id && Date.parse(r.startedAt) <= startedAt && !(r.startedAt === current.results.ingest.startedAt && r.analyzedAt === current.results.analyzedAt))
        .sort((a, b) => Date.parse(a.startedAt) - Date.parse(b.startedAt));
}

async function fillBaselines() {
    const select = $('#rep-baseline');
    const runs = await earlierRuns();
    select.replaceChildren(
        element('option', { value: '', text: runs.length ? 'Previous run (automatic)' : 'No earlier run in this browser' }),
        element('option', { value: 'none', text: 'Nothing (no comparison, no trend)' }),
        ...runs.slice().reverse().map(r => element('option', { value: r.id, text: `${formatDate(r.startedAt)}, score ${r.score ?? 'none'}` }))
    );
}

async function renderReport() {
    const preferences = readStorage(PREFERENCES_KEY, {});
    const title = $('#rep-title').value.trim();
    const organization = $('#rep-org').value.trim();
    const choice = $('#rep-baseline').value;
    const runs = choice === 'none' ? [] : await earlierRuns();
    const baseline = choice && choice !== 'none' ? runs.find(r => r.id === choice) : null;
    setReportReady(false);
    try {
        const { html } = await call('report', {
            resultsText: current.resultsText,
            history: runs.map(r => ({ resultsText: r.resultsText, analyzedAt: r.analyzedAt })),
            baselineText: baseline?.resultsText ?? null,
            title, organization
        });
        reportHtml = html;
        $('#viewer-title').textContent = `${title || 'Azure security assessment'}, ${organization || current.results.ingest.subscriptionName || current.results.ingest.subscriptionId}${runs.length ? `, with ${runs.length} earlier run${runs.length === 1 ? '' : 's'}` : ''}`;
        renderPreview(current.results);
        setReportReady(true);
        if (!$('#viewer').hidden) { loadFrame(); }
        writeStorage(PREFERENCES_KEY, { ...preferences, title, organization });
    } catch (e) {
        setReportReady(false, 'Report not available');
        showBanner('error', ['The report could not be generated.', e.message]);
    }
}

//#endregion

//#region keeping a run alive

//The collected data exists only in this tab. While an assessment runs the page shows a note, asks before the tab is
//closed or reloaded, holds a Web Lock (Chrome and Edge do not freeze or discard a background tab that holds one),
//keeps the screen awake while the tab is visible, and leaves a marker in sessionStorage that reports a run the browser
//cut off (a discarded tab reloads with its sessionStorage).
const RUN_KEY = 'azcmply.run';
const PAGE_TITLE = document.title;
let guarding = false;
let wakeLock = null;
let releaseLock = null;

function confirmLeave(event) { event.preventDefault(); event.returnValue = ''; }

async function keepScreenAwake() {
    if (!guarding || wakeLock || document.visibilityState !== 'visible' || !navigator.wakeLock) { return; }
    try {
        wakeLock = await navigator.wakeLock.request('screen');
        wakeLock.addEventListener('release', () => { wakeLock = null; });
    } catch { wakeLock = null; }
}

function guardRun(subscription) {
    guarding = true;
    $('#keep-open').hidden = false;
    document.title = `Running: ${PAGE_TITLE}`;
    window.addEventListener('beforeunload', confirmLeave);
    try { sessionStorage.setItem(RUN_KEY, JSON.stringify({ subscription, startedAt: new Date().toISOString() })); } catch { /* no marker, no report after a discard */ }
    navigator.locks?.request('azcmply-run', () => new Promise(resolve => { releaseLock = resolve; })).catch(() => { });
    keepScreenAwake();
}

function releaseRun() {
    guarding = false;
    $('#keep-open').hidden = true;
    document.title = PAGE_TITLE;
    window.removeEventListener('beforeunload', confirmLeave);
    try { sessionStorage.removeItem(RUN_KEY); } catch { }
    releaseLock?.();
    releaseLock = null;
    wakeLock?.release().catch(() => { });
    wakeLock = null;
}

//a run whose marker survived was cut off: the tab was reloaded or discarded while it ran
function reportInterruptedRun() {
    let run = null;
    try { run = JSON.parse(sessionStorage.getItem(RUN_KEY) ?? 'null'); sessionStorage.removeItem(RUN_KEY); } catch { }
    if (!run) { return; }
    showBanner('error', [`The assessment of ${run.subscription} that started ${formatDate(run.startedAt)} did not finish: the tab was reloaded, or the browser unloaded it.`,
        'Run it again and keep this tab open until it is done.']);
}

//the browser releases the screen wake lock when the tab is hidden; take it again when the tab is back
document.addEventListener('visibilitychange', keepScreenAwake);

//#endregion

//#region running

async function analyzeFolder(folder, source, save) {
    setPhase('analysis', 'active');
    const analysis = await call('analyze', { folder });
    setPhase('analysis', 'done');
    appendLog(`Analysis done in ${analysis.seconds} s`);
    let id = null;
    if (save) { id = (await store.saveAnalysis(analysis.resultsText, source)).id; await renderHistory(); }
    setPhase('report', 'active');
    await showResult({ ...analysis, ingestFolder: folder, source, id });
    setPhase('report', 'done');
}

async function runAssessment() {
    if (busy) { return; }
    const subscriptionId = $('#subscription').value;
    if (!subscriptionId) { showBanner('error', ['Choose a subscription first.']); return; }
    hideBanner();
    const settings = auth.settings();
    const options = {
        environment: settings.cloud,
        activityLogDays: Number($('#opt-days').value),
        skipGraph: !$('#opt-graph').checked,
        skipResourceGraph: !$('#opt-rg').checked,
        clientId: settings.clientId,
        authMethod: 'Delegated'
    };
    writeStorage(PREFERENCES_KEY, { ...readStorage(PREFERENCES_KEY, {}), subscriptionId, organization: $('#opt-org').value.trim() });
    $('#rep-org').value = $('#opt-org').value.trim();
    if (!options.skipGraph) {
        try { await auth.getToken('Graph'); }
        catch (e) {
            showBanner('error', ['Microsoft Graph access was refused, so the Entra ID checks cannot run.', e.message, 'Grant admin consent, or clear "Entra ID enrichment" to assess without it (those tests then report Unknown).'], e.consent ? { href: auth.adminConsentUrl(settings), text: 'Admin consent for this app' } : null);
            return;
        }
    }
    const phases = ['subscription', 'resources'];
    if (!options.skipResourceGraph) { phases.push('resourceGraph'); }
    if (options.activityLogDays > 0) { phases.push('activityLog'); }
    if (!options.skipGraph) { phases.push('graph'); }
    phases.push('analysis', 'report');
    setBusy(true);
    startProgress('Collecting and analysing', phases, true);
    guardRun($('#subscription').selectedOptions[0]?.textContent || subscriptionId);
    setPhase('subscription', 'active');
    try {
        const ingest = await call('ingest', { subscriptionId, options });
        appendLog(`Collected ${ingest.resources} resources; ${ingest.failedRequests} requests failed (listed in failures.json of the ingestion)`);
        showIssues(ingest.issues ?? [], ingest.failedRequests);
        $('#cancel').hidden = true;
        await analyzeFolder(ingest.folder, 'browser', true);
        $('#progress-title').textContent = 'Done';
    } catch (e) {
        failActivePhase();
        $('#progress-title').textContent = e.cancelled ? 'Cancelled' : 'Stopped';
        if (!e.cancelled) { showBanner('error', ['The assessment stopped.', e.message]); }
    } finally {
        releaseRun();
        setBusy(false);
        $('#cancel').hidden = true;
    }
}

async function runDemo() {
    if (busy) { return; }
    hideBanner();
    setBusy(true);
    startProgress('Demo', ['demo', 'analysis', 'report'], false);
    try {
        setPhase('demo', 'active');
        const demo = await call('demo');
        setPhase('demo', 'done');
        await analyzeFolder(demo.folder, 'demo', false);
        $('#progress-title').textContent = 'Done';
    } catch (e) {
        failActivePhase();
        showBanner('error', ['The demo could not run.', e.message]);
    } finally {
        setBusy(false);
    }
}

//#endregion

//#region history

//the posture score of a subscription up to a run, as a sparkline with its direction; a dash for fewer than two scored runs.
//Direction is shown by an arrow and the signed change too, never by the red or green alone
function trendCell(series) {
    if (series.length < 2) { return element('span', { class: 'muted', text: '-', title: 'One run so far' }); }
    const width = 96, height = 28, pad = 5;
    const scores = series.map(r => r.score);
    let low = Math.min(...scores), high = Math.max(...scores);
    if (high - low < 1) { low -= 1; high += 1; }
    const x = i => pad + i * (width - 2 * pad) / (series.length - 1);
    const y = v => height - pad - (v - low) / (high - low) * (height - 2 * pad);
    const first = scores[0], last = scores[scores.length - 1];
    const delta = Math.round((last - first) * 10) / 10;
    const direction = delta > 0 ? 'up' : delta < 0 ? 'down' : 'flat';
    const deltaText = `${delta > 0 ? '+' : ''}${delta}`;
    const summary = `Posture score over ${series.length} runs: ${first} to ${last} (${deltaText})`;
    const chart = svg('svg', { class: 'spark', viewBox: `0 0 ${width} ${height}`, width: String(width), height: String(height), role: 'img', 'aria-label': summary },
        svg('polyline', { class: 'spark-line', points: scores.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ') }),
        svg('circle', { class: 'spark-dot', cx: x(scores.length - 1).toFixed(1), cy: y(last).toFixed(1), r: '3.5' }),
        //hover targets per run, wider than the marks
        ...series.map((run, i) => {
            const half = (width - 2 * pad) / (series.length - 1) / 2;
            return svg('rect', { class: 'spark-hit', x: Math.max(0, x(i) - half).toFixed(1), y: '0', width: (2 * half).toFixed(1), height: String(height) },
                svg('title', {}, `${formatDate(run.startedAt)}: ${run.score}`));
        })
    );
    return element('span', { class: `trend ${direction}`, title: summary },
        chart,
        element('span', { class: 'delta' }, element('span', { class: 'arrow', 'aria-hidden': 'true', text: direction === 'up' ? '▲' : direction === 'down' ? '▼' : '▶' }), deltaText));
}

function runOrder(a, b) { return Date.parse(a.startedAt) - Date.parse(b.startedAt) || (a.analyzedAt ?? '').localeCompare(b.analyzedAt ?? ''); }

async function renderHistory() {
    const rows = $('#history-rows');
    let runs = [];
    try { runs = await store.listAnalyses(); }
    catch (e) { rows.replaceChildren(element('tr', {}, element('td', { colspan: '8', class: 'empty', text: `History is not available in this browser (${e.message}).` }))); return; }
    if (!runs.length) { rows.replaceChildren(element('tr', {}, element('td', { colspan: '8', class: 'empty', text: 'No analyses yet.' }))); return; }
    const bySubscription = new Map();
    for (const run of runs) {
        const key = String(run.subscriptionId).toLowerCase();
        if (!bySubscription.has(key)) { bySubscription.set(key, []); }
        bySubscription.get(key).push(run);
    }
    for (const list of bySubscription.values()) { list.sort(runOrder); }
    rows.replaceChildren(...runs.map(run => {
        const series = bySubscription.get(String(run.subscriptionId).toLowerCase()).filter(r => runOrder(r, run) <= 0 && typeof r.score === 'number');
        return element('tr', {},
            element('td', {}, formatDate(run.startedAt), element('span', { class: 'sub', text: `analysed ${formatDate(run.analyzedAt)}` })),
            element('td', {}, run.subscriptionName ?? '', element('span', { class: 'sub', text: run.subscriptionId })),
            element('td', { class: 'num', text: run.score === null || run.score === undefined ? '-' : String(run.score) }),
            element('td', { class: 'trend-cell' }, trendCell(typeof run.score === 'number' ? series : [])),
            element('td', { class: 'num', text: String(run.tests?.Fail ?? '-') }),
            element('td', { class: 'num', text: String(run.testCount ?? '-') }),
            element('td', {}, element('span', { class: 'pill', text: run.source ?? '' })),
            element('td', { class: 'actions' },
                element('button', {
                    type: 'button', class: 'btn small', text: 'View report', onclick: async () => {
                        if (busy) { return; }
                        const full = await store.getAnalysis(run.id);
                        await showResult({ resultsText: full.resultsText, id: run.id, source: run.source }, { open: true });
                    }
                }),
                element('button', {
                    type: 'button', class: 'btn ghost small', text: 'Delete', 'aria-label': `Delete the analysis of ${formatDate(run.startedAt)}`, onclick: async () => {
                        if (!confirm(`Delete the analysis of ${run.subscriptionName} collected ${formatDate(run.startedAt)} from this browser?`)) { return; }
                        await store.deleteAnalysis(run.id);
                        await renderHistory();
                    }
                })
            )
        );
    }));
}

async function exportHistory() {
    const runs = await store.listAnalyses();
    if (!runs.length) { showBanner('info', ['There is no history to export yet.']); return; }
    const entries = [];
    for (const run of runs) {
        const full = await store.getAnalysis(run.id);
        entries.push({ folder: safeName(`${run.subscriptionId}_${run.startedAt}_${run.analyzedAt}`), resultsText: full.resultsText });
    }
    const { blob } = await call('exportHistory', { entries });
    download(blob, `azcmply-history-${new Date().toISOString().slice(0, 10)}.zip`);
}

//#endregion

//#region start

async function start() {
    applyTheme(readStorage(THEME_KEY, 'auto'));
    $('#theme').addEventListener('click', () => {
        const next = THEMES[(THEMES.indexOf($('#theme').dataset.theme ?? 'auto') + 1) % THEMES.length];
        applyTheme(next);
        writeStorage(THEME_KEY, next);
    });
    $('#docs-link').href = config.documentation;
    const preferences = readStorage(PREFERENCES_KEY, {});
    $('#opt-org').value = preferences.organization ?? '';
    $('#rep-org').value = preferences.organization ?? '';
    $('#rep-title').value = preferences.title ?? '';
    renderSettings();

    $('#save-settings').addEventListener('click', saveSettings);
    $('#reset-settings').addEventListener('click', () => { writeStorage(SETTINGS_KEY, {}); renderSettings(); });
    $('#sign-in').addEventListener('click', () => {
        const s = loadSettings();
        if (!s.clientId) { showBanner('error', ['Enter the application id of your app registration first, under "App registration and tenant".']); $('#app-settings').open = true; return; }
        auth.signIn(s);
    });
    $('#sign-out').addEventListener('click', () => { auth.signOut(); renderAccount(); });
    $('#run').addEventListener('click', runAssessment);
    $('#cancel').addEventListener('click', () => call('cancel'));
    $('#demo').addEventListener('click', runDemo);
    $('#history-export').addEventListener('click', () => exportHistory().catch(e => showBanner('error', ['Export failed.', e.message])));
    $('#history-clear').addEventListener('click', async () => {
        if (!confirm('Remove every analysis from the history in this browser?')) { return; }
        await store.clearAnalyses();
        await renderHistory();
    });
    $('#rep-refresh').addEventListener('click', () => current && renderReport());
    $('#preview').addEventListener('click', openViewer);
    $('#view-report').addEventListener('click', openViewer);
    $('#viewer-close').addEventListener('click', closeViewer);
    $('#viewer-download').addEventListener('click', downloadReport);
    document.addEventListener('keydown', event => {
        if ($('#viewer').hidden) { return; }
        if (event.key === 'Escape') { event.preventDefault(); closeViewer(); return; }
        //keep keyboard focus inside the viewer while it is open
        if (event.key === 'Tab') {
            const stops = [$('#viewer-download'), $('#viewer-close'), $('#report-frame')].filter(el => !el.disabled);
            const index = stops.indexOf(document.activeElement);
            if (event.shiftKey && index <= 0) { event.preventDefault(); stops[stops.length - 1].focus(); }
            else if (!event.shiftKey && (index === stops.length - 1 || index < 0)) { event.preventDefault(); stops[0].focus(); }
        }
    });

    call('info').then(info => {
        $('#version').textContent = `v${info.version}`;
        const boot = document.querySelector('script[src*="js/boot.js"]');
        const build = boot ? new URL(boot.src).searchParams.get('v') : null;
        if (build) { $('#version').title = `Build ${build}`; }
    });
    renderHistory();

    let redirect = null;
    try { redirect = await auth.completeRedirect(); }
    catch (e) { redirect = { error: e.message, consent: e.consent }; }
    if (redirect?.adminConsent) { showBanner('ok', ['Admin consent was granted. Sign in to run an assessment.']); }
    else if (redirect?.error) {
        const s = loadSettings();
        showBanner('error', ['Sign-in did not complete.', redirect.error], s.clientId ? { href: auth.adminConsentUrl(s), text: 'Admin consent for this app' } : null);
    }
    auth.restore();
    renderAccount();
    reportInterruptedRun();
    //a link to the page with #demo opens the demo straight away
    if (location.hash === '#demo') { runDemo(); }
}

start();

//#endregion
