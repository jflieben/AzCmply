//Analysis history in this browser (IndexedDB): the results.json of every run, which is all the report needs for its
//trend and for the changes since the previous run. Raw ingestion data is not kept; it can be downloaded as a zip.
const DB_NAME = 'azcmply';
const DB_VERSION = 2;
const STORE = 'analyses';

function open() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        //a new database version starts with an empty history
        request.onupgradeneeded = () => {
            const db = request.result;
            if (db.objectStoreNames.contains(STORE)) { db.deleteObjectStore(STORE); }
            db.createObjectStore(STORE, { keyPath: 'id' }).createIndex('subscription', 'subscriptionKey');
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function run(mode, action) {
    const db = await open();
    try {
        return await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE, mode);
            const result = action(tx.objectStore(STORE));
            tx.oncomplete = () => resolve(result?.result);
            tx.onerror = () => reject(tx.error);
            tx.onabort = () => reject(tx.error);
        });
    } finally { db.close(); }
}

//the summary of a results.json kept next to its text, so the history list does not parse every run
function summarize(resultsText) {
    const results = JSON.parse(resultsText);
    return {
        id: `${results.ingest.subscriptionId}|${results.ingest.startedAt}|${results.analyzedAt}`.toLowerCase(),
        subscriptionId: results.ingest.subscriptionId,
        subscriptionKey: results.ingest.subscriptionId.toLowerCase(),
        subscriptionName: results.ingest.subscriptionName,
        startedAt: results.ingest.startedAt,
        analyzedAt: results.analyzedAt,
        testCount: results.analyzer.tests,
        score: results.summary.postureScore,
        tests: results.summary.tests
    };
}

export async function saveAnalysis(resultsText, source) {
    const entry = { ...summarize(resultsText), source, resultsText };
    await run('readwrite', store => store.put(entry));
    return entry;
}

//all runs without their results text, newest first
export async function listAnalyses() {
    const all = await run('readonly', store => store.getAll()) ?? [];
    return all.map(({ resultsText, ...rest }) => rest).sort((a, b) => b.startedAt.localeCompare(a.startedAt) || b.analyzedAt.localeCompare(a.analyzedAt));
}

export async function getAnalysis(id) { return run('readonly', store => store.get(id)); }

//earlier runs of a subscription with their results text, for the report history
export async function analysesOf(subscriptionId) {
    const all = await run('readonly', store => store.index('subscription').getAll(String(subscriptionId).toLowerCase())) ?? [];
    return all;
}

export async function deleteAnalysis(id) { await run('readwrite', store => store.delete(id)); }

export async function clearAnalyses() { await run('readwrite', store => store.clear()); }
