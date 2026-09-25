//Node side of Test-WebParity.ps1: runs the generated scripts on the browser runtime against files on disk.
//  node parity.mjs analyze <ingest folder> <output folder>
//  node parity.mjs report <analysis folder> <output html> [history folder]
//  node parity.mjs compare <baseline folder> <current folder> <output json>
//  node parity.mjs diffjson <a.json> <b.json> [ignored top level key ...]
import fs from 'node:fs';
import path from 'node:path';
import { R, VFS } from '../site/js/runtime/index.js';
import { mount } from '../site/generated/index.js';

const [command, ...args] = process.argv.slice(2);
const log = [];
const host = { write: t => log.push(t), warn: t => log.push('WARNING: ' + t) };

function newVfs() {
    const vfs = new VFS();
    mount(vfs);
    R.configure({ vfs, host });
    return vfs;
}

//copies a folder from disk into the runtime file system, keeping modification times
function load(vfs, folder, virtualFolder) {
    for (const entry of fs.readdirSync(folder, { withFileTypes: true, recursive: true })) {
        if (!entry.isFile()) { continue; }
        const full = path.join(entry.parentPath ?? entry.path, entry.name);
        const relative = path.relative(folder, full).split(path.sep).join('/');
        vfs.writeText(`${virtualFolder}/${relative}`, fs.readFileSync(full, 'utf8').replace(/^\uFEFF/, ''), fs.statSync(full).mtimeMs);
    }
}

function save(vfs, virtualPath, file) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, vfs.readText(virtualPath));
}

function deepDiff(a, b, where, ignore) {
    if (a === b) { return null; }
    if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') {
        if (typeof a === 'number' && typeof b === 'number' && a === b) { return null; }
        return `${where}: ${JSON.stringify(a)?.slice(0, 300)} <> ${JSON.stringify(b)?.slice(0, 300)}`;
    }
    if (Array.isArray(a) !== Array.isArray(b)) { return `${where}: array <> object`; }
    if (Array.isArray(a)) {
        if (a.length !== b.length) { return `${where}: length ${a.length} <> ${b.length}`; }
        for (let i = 0; i < a.length; i++) { const d = deepDiff(a[i], b[i], `${where}[${i}]`, ignore); if (d) { return d; } }
        return null;
    }
    const ka = Object.keys(a).filter(k => !ignore.has(k)), kb = Object.keys(b).filter(k => !ignore.has(k));
    if (ka.join('|') !== kb.join('|')) { return `${where}: keys [${ka.join(',')}] <> [${kb.join(',')}]`; }
    for (const k of ka) { const d = deepDiff(a[k], b[k], `${where}.${k}`, ignore); if (d) { return d; } }
    return null;
}

const started = Date.now();
try {
    switch (command) {
        case 'analyze': {
            //pairs of ingest folder and output folder, analysed one after the other in this process
            for (let i = 0; i < args.length; i += 2) {
                const [ingest, out] = [args[i], args[i + 1]];
                const runStarted = Date.now();
                const vfs = newVfs();
                const name = path.basename(ingest);
                load(vfs, ingest, `/data/ingest/${name}`);
                const result = R.runScript('/app/Analyze/Invoke-AzureAnalyze.ps1', { IngestPath: `/data/ingest/${name}`, OutputPath: '/data/analysis' });
                for (const file of ['results.json', 'tests.csv', 'findings.csv']) { save(vfs, `/data/analysis/${name}/${file}`, path.join(out, file)); }
                if (args.length === 2) { console.log(`analyzed in ${Date.now() - runStarted} ms: ${R.str(R.m(result[0], 'Tests'))} tests`); }
            }
            if (args.length > 2) { console.log(`analyzed ${args.length / 2} ingestions in ${Date.now() - started} ms`); }
            break;
        }
        case 'report': {
            const [analysis, outHtml, history] = args;
            const vfs = newVfs();
            load(vfs, analysis, '/data/current');
            const named = { AnalysisPath: '/data/current', OutputPath: '/data/report.html' };
            if (history) { load(vfs, history, '/data/history'); named.HistoryPath = '/data/history'; }
            R.runScript('/app/Report/New-AzureSecurityReport.ps1', named);
            save(vfs, '/data/report.html', outHtml);
            console.log(`report in ${Date.now() - started} ms`);
            break;
        }
        case 'compare': {
            const [baseline, current, outJson] = args;
            const vfs = newVfs();
            load(vfs, baseline, '/data/baseline');
            load(vfs, current, '/data/current');
            R.runScript('/app/Analyze/Compare-AzureAnalysis.ps1', { Baseline: '/data/baseline', Current: '/data/current', OutputPath: '/data/comparison.json' });
            save(vfs, '/data/comparison.json', outJson);
            console.log(`compared in ${Date.now() - started} ms`);
            break;
        }
        case 'diffjson': {
            const [a, b, ...ignored] = args;
            const d = deepDiff(JSON.parse(fs.readFileSync(a, 'utf8').replace(/^\uFEFF/, '')), JSON.parse(fs.readFileSync(b, 'utf8').replace(/^\uFEFF/, '')), '$', new Set(ignored));
            console.log(d ? `DIFFERENT ${d}` : 'SAME');
            process.exitCode = d ? 1 : 0;
            break;
        }
        default: throw new Error(`unknown command ${command}`);
    }
} catch (e) {
    console.log(`FAILED ${e && e.stack ? e.stack : e}`);
    process.exitCode = 2;
}
if (log.length && process.env.PARITY_LOG) { console.log(log.join('\n')); }
