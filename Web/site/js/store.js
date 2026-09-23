//Analysis history in this browser (IndexedDB): the results.json of every run, which is all the report needs for its
//trend and for the changes since the previous run. Raw ingestion data is not kept; it can be downloaded as a zip.
const DB_NAME = 'azcmply';
const STORE = 'analyses';

function open() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, 1);
        request.onupgradeneeded = () => {
            const store = request.result.createObjectStore(STORE, { keyPath: 'id' });
            store.createIndex('subscription', 'subscriptionKey');
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
export function summarize(resultsText) {
    const results = JSON.parse(resultsText.replace(/^\uFEFF/, ''));
    if (!results?.ingest?.subscriptionId || !results.summary || !Array.isArray(results.tests)) {
        throw new Error('This is not a results.json of an AzCmply analysis.');
    }
    return {
        id: `${results.ingest.subscriptionId}|${results.ingest.startedAt}|${results.analyzedAt}`.toLowerCase(),
        subscriptionId: results.ingest.subscriptionId,
        subscriptionKey: String(results.ingest.subscriptionId).toLowerCase(),
        subscriptionName: results.ingest.subscriptionName ?? results.ingest.subscriptionId,
        tenantId: results.ingest.tenantId ?? null,
        startedAt: results.ingest.startedAt,
        analyzedAt: results.analyzedAt,
        analyzerVersion: results.analyzer?.version ?? null,
        testCount: results.analyzer?.tests ?? results.tests.length,
        score: results.summary.postureScore ?? null,
        tests: results.summary.tests
    };
}

export async function saveAnalysis(resultsText, source) {
    const entry = { ...summarize(resultsText), source, savedAt: new Date().toISOString(), resultsText };
    await run('readwrite', store => store.put(entry));
    return entry;
}

//all runs without their results text, newest first
export async function listAnalyses() {
    const all = await run('readonly', store => store.getAll()) ?? [];
    return all.map(({ resultsText, ...rest }) => rest).sort((a, b) => (b.startedAt ?? '').localeCompare(a.startedAt ?? '') || (b.analyzedAt ?? '').localeCompare(a.analyzedAt ?? ''));
}

export async function getAnalysis(id) { return run('readonly', store => store.get(id)); }

//earlier runs of a subscription with their results text, for the report history
export async function analysesOf(subscriptionId) {
    const all = await run('readonly', store => store.index('subscription').getAll(String(subscriptionId).toLowerCase())) ?? [];
    return all;
}

export async function deleteAnalysis(id) { await run('readwrite', store => store.delete(id)); }

export async function clearAnalyses() { await run('readwrite', store => store.clear()); }
