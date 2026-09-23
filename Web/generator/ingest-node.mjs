//Runs the browser ingestion under node with a service principal, and writes the result to disk like the PowerShell
//ingestion does. Used by Test-WebIngestParity.ps1.
//  node ingest-node.mjs <credentials file> <output folder> <folder name> [activity log days]
//The credentials file holds 'key: value' lines: appid, tenantid, secret, subscriptionid. Its values are never printed.
import fs from 'node:fs';
import path from 'node:path';
import { VFS } from '../site/js/runtime/index.js';
import plan from '../site/generated/ingest-plan.js';
import { runIngest, ingestFiles } from '../site/js/ingest.js';

const [credentialsFile, outputFolder, folderName, days] = process.argv.slice(2);
const settings = {};
for (const line of fs.readFileSync(credentialsFile, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Za-z]+)\s*:\s*(.*?)\s*$/.exec(line);
    if (m) { settings[m[1].toLowerCase()] = m[2]; }
}
for (const key of ['appid', 'tenantid', 'secret', 'subscriptionid']) {
    if (!settings[key]) { console.error(`The credentials file has no '${key}'`); process.exit(2); }
}

const endpoints = plan.cloudEndpoints.AzureCloud;
const cache = {};
async function getToken(resource) {
    const cached = cache[resource];
    if (cached && cached.expires > Date.now() + 300000) { return cached.token; }
    const body = new URLSearchParams({ client_id: settings.appid, client_secret: settings.secret, scope: `${endpoints[resource]}/.default`, grant_type: 'client_credentials' });
    const response = await fetch(`${endpoints.Login}/${settings.tenantid}/oauth2/v2.0/token`, { method: 'POST', body });
    const json = await response.json();
    if (!response.ok) { throw new Error(`Failed to acquire a ${resource} token: ${json.error_description ?? json.error}`); }
    cache[resource] = { token: json.access_token, expires: Date.now() + json.expires_in * 1000 };
    return json.access_token;
}

const vfs = new VFS();
const started = Date.now();
const result = await runIngest({
    plan, getToken, vfs, subscriptionId: settings.subscriptionid, folderName, activityLogDays: days === undefined ? 90 : Number(days),
    authMethod: 'ClientSecret', clientId: settings.appid, collector: 'AzCmply web (node)',
    log: t => console.log(`${new Date().toISOString().slice(11, 19)} ${t}`)
});
for (const file of ingestFiles(vfs, result.root)) {
    const target = path.join(outputFolder, folderName, file.name);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, file.text);
}
console.log(`Done in ${Math.round((Date.now() - started) / 1000)} s: ${result.resources} resources, ${result.failedRequests} failed requests`);
