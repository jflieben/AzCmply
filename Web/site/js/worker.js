//Runs the ingestion, the generated analysis and the generated report away from the page, so the page stays responsive.
//Holds the collected data in memory; nothing leaves this browser except the calls to the Microsoft APIs.
import { R, VFS } from './runtime/index.js';
import { mount, version } from '../generated/index.js';
import plan from '../generated/ingest-plan.js';
import { runIngest, ingestFiles } from './ingest.js';
import { writeZip } from './zip.js';

const ANALYZER = '/app/Analyze/Invoke-AzureAnalyze.ps1';
const REPORT = '/app/Report/New-AzureSecurityReport.ps1';

const vfs = new VFS();
mount(vfs);
R.configure({
    vfs,
    host: {
        write: text => post({ type: 'log', text }),
        warn: text => post({ type: 'log', text: `WARNING: ${text}`, level: 'warn' }),
        error: text => post({ type: 'log', text: `ERROR: ${text}`, level: 'error' })
    }
});

let abort = null;
const tokenRequests = new Map();
let nextTokenRequest = 1;

function post(message, transfer) { self.postMessage(message, transfer ?? []); }

function getToken(resource) {
    return new Promise((resolve, reject) => {
        const rid = nextTokenRequest++;
        tokenRequests.set(rid, { resolve, reject });
        post({ type: 'token', rid, resource });
    });
}

//#region demo data

async function loadDemo() {
    const demo = (await import('../generated/demo-ingest.js')).default;
    const folder = 'demo_fixture-noncompliant';
    vfs.remove(`/data/ingest/${folder}`);
    for (const [name, value] of Object.entries(demo)) { vfs.writeJson(`/data/ingest/${folder}/${name}`, value); }
    return { kind: 'ingest', folder, files: Object.keys(demo).length };
}

//#endregion

//#region analysis and report

function analyze(folder) {
    const started = Date.now();
    vfs.remove(`/data/analysis/${folder}`);
    R.runScript(ANALYZER, { IngestPath: `/data/ingest/${folder}`, OutputPath: '/data/analysis', FolderName: folder });
    const base = `/data/analysis/${folder}`;
    return {
        folder,
        seconds: Math.round((Date.now() - started) / 100) / 10,
        resultsText: vfs.readText(`${base}/results.json`),
        testsCsv: vfs.readText(`${base}/tests.csv`),
        findingsCsv: vfs.readText(`${base}/findings.csv`)
    };
}

//the report of one results.json; history holds earlier results.json texts of the same subscription
function report({ resultsText, history = [], baselineText = null, title, organization }) {
    for (const folder of ['/data/report', '/data/history', '/data/baseline']) { vfs.remove(folder); }
    vfs.writeText('/data/report/current/results.json', resultsText);
    const named = { AnalysisPath: '/data/report/current', OutputPath: '/data/report/report.html' };
    history.forEach((item, i) => vfs.writeText(`/data/history/run${String(i).padStart(4, '0')}/results.json`, item.resultsText, Date.parse(item.analyzedAt) || 0));
    if (history.length) { named.HistoryPath = '/data/history'; }
    if (baselineText) {
        vfs.writeText('/data/baseline/results.json', baselineText);
        named.BaselinePath = '/data/baseline';
    }
    if (title) { named.Title = title; }
    if (organization) { named.Organization = organization; }
    R.runScript(REPORT, named);
    return { html: vfs.readText('/data/report/report.html') };
}

//#endregion

const handlers = {
    info: () => ({ version, cloudEndpoints: plan.cloudEndpoints }),
    demo: () => loadDemo(),
    ingest: async ({ subscriptionId, options }) => {
        abort = new AbortController();
        try {
            const result = await runIngest({
                plan, getToken, vfs, subscriptionId, ...options, collector: `AzCmply web ${version}`, signal: abort.signal,
                log: text => post({ type: 'log', text }),
                progress: p => post({ type: 'progress', ...p })
            });
            return { kind: 'ingest', folder: result.folder, resources: result.resources, failedRequests: result.failedRequests };
        } finally { abort = null; }
    },
    cancel: () => { abort?.abort(); return true; },
    analyze: ({ folder }) => analyze(folder),
    report: request => report(request),
    exportIngest: async ({ folder }) => {
        const blob = await writeZip(ingestFiles(vfs, `/data/ingest/${folder}`).map(f => ({ name: `${folder}/${f.name}`, text: f.text })));
        return { blob };
    },
    exportHistory: async ({ entries }) => ({ blob: await writeZip(entries.map(e => ({ name: `${e.folder}/results.json`, text: e.resultsText }))) }),
    discard: ({ folder }) => { vfs.remove(`/data/ingest/${folder}`); vfs.remove(`/data/analysis/${folder}`); return true; }
};

self.onmessage = async event => {
    const message = event.data;
    if (message.type === 'token') {
        const pending = tokenRequests.get(message.rid);
        tokenRequests.delete(message.rid);
        if (pending) { if (message.error) { pending.reject(new Error(message.error)); } else { pending.resolve(message.token); } }
        return;
    }
    const handler = handlers[message.op];
    try {
        if (!handler) { throw new Error(`Unknown operation ${message.op}`); }
        const value = await handler(message);
        post({ type: 'result', id: message.id, ok: true, value });
    } catch (e) {
        post({ type: 'result', id: message.id, ok: false, error: e?.name === 'AbortError' ? 'Cancelled.' : (e?.message ?? String(e)), cancelled: e?.name === 'AbortError' });
    }
};

post({ type: 'ready' });
