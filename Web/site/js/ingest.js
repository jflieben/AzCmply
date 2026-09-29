//Browser ingestion: collects the same data as Ingest\Invoke-AzureIngest.ps1, into the same folder layout, in memory.
//What is collected (endpoints, api versions, child resources, Graph properties) comes from the generated collection plan;
//how it is collected mirrors the PowerShell functions named in the comments. Keep the two in step: a change to the
//collection logic of the PowerShell ingestion needs the same change here (the collection maps need nothing, they are
//generated). Test-WebIngestParity.ps1 compares both against a live subscription.
import { parseJson, toJson } from './runtime/json.js';
import { PSDate } from './runtime/types.js';
import { formatDate } from './runtime/convert.js';

const GUID = /[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}/g;
const PRINCIPAL_PROPERTY = /"(?:principalId|principalIds|objectId|sid|adminGroupObjectIDs)"\s*:\s*(\[[^\]]*\]|"[^"]*")/gi;
const DENIED = /"code"\s*:\s*"(AccessDenied|AuthorizationFailed|LinkedAuthorizationFailed|Forbidden)"/i;

function sleep(ms, signal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(resolve, ms);
        signal?.addEventListener('abort', () => { clearTimeout(timer); reject(new DOMException('Cancelled', 'AbortError')); }, { once: true });
    });
}

export function tokenClaims(token) {
    const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payload + '='.repeat((4 - payload.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
}

function isoNow() { return formatDate(new PSDate(Date.now(), 'Utc'), 'o'); }

//Get-SafeFileName: <sanitized name>_<first 8 hex chars of the SHA-256 of the lowercase id>
async function safeFileName(name, id) {
    let safe = String(name ?? '').replace(/[^A-Za-z0-9._-]/g, '_');
    if (safe.length > 60) { safe = safe.slice(0, 60); }
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(id.toLowerCase())));
    return `${safe}_${Array.from(hash.slice(0, 4), b => b.toString(16).padStart(2, '0')).join('')}`;
}

//Get-ChildTypeSegments: 'blobServices/default/containers' -> 'blobServices/containers'
function childTypeSegments(path) { return path.split('/').filter((_, i) => i % 2 === 0).join('/'); }

//runs async work over items with a fixed number of workers, keeping result order
async function pool(items, limit, worker, signal) {
    const results = new Array(items.length);
    let next = 0;
    async function run() {
        while (next < items.length) {
            signal?.throwIfAborted();
            const i = next++;
            results[i] = await worker(items[i], i);
        }
    }
    await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run));
    return results;
}

export async function runIngest(options) {
    const {
        plan, getToken, subscriptionId, vfs, environment = 'AzureCloud', activityLogDays = 90, skipGraph = false,
        skipResourceGraph = false, throttleLimit = 8, authMethod = 'Delegated', clientId = null, collector = 'AzCmply web',
        log = () => { }, progress = () => { }, signal, folderName
    } = options;
    const endpoints = plan.cloudEndpoints[environment];
    if (!endpoints) { throw new Error(`Unknown environment ${environment}`); }
    const core = plan.coreApiVersions;
    const failures = [];
    const startDate = new PSDate(Date.now(), 'Utc');
    const startedAt = formatDate(startDate, 'o');
    //metric query windows ('start/end'), newest first; the metrics API returns at most about 30 days per query
    const metricsTimespans = [];
    for (let daysBack = 0; daysBack < plan.metricsDays; daysBack += plan.metricsWindowDays) {
        const from = startDate.addMs(-Math.min(daysBack + plan.metricsWindowDays, plan.metricsDays) * 86400000);
        metricsTimespans.push(`${formatDate(from, 'yyyy-MM-ddTHH:mm:ssZ')}/${formatDate(startDate.addMs(-daysBack * 86400000), 'yyyy-MM-ddTHH:mm:ssZ')}`);
    }
    const folder = folderName ?? `${subscriptionId}_${formatDate(startDate, 'yyyyMMdd-HHmmss')}`;
    const root = `/data/ingest/${folder}`;
    const write = (relative, value) => vfs.writeJson(`${root}/${relative}`, value);
    const sections = {};
    const counts = {};
    const principalIds = new Set();
    let caller = {};
    let subscriptionInfo = null;
    let runStatus = 'failed';
    let fatalError = null;
    let tenantId = null;

    //#region requests

    //Add-RequestFailure
    function addFailure(uri, method, statusCode, errorCode, message, context) {
        const category = statusCode === 0 ? 'network' : [401, 403].includes(statusCode) ? 'accessDenied' : statusCode === 404 ? 'notFound'
            : statusCode === 429 ? 'throttled' : statusCode >= 500 ? 'serverError' : statusCode >= 400 ? 'badRequest' : 'other';
        if (message && message.length > 2000) { message = message.slice(0, 2000); }
        const failure = { time: isoNow(), category, statusCode, errorCode: errorCode ?? null, message: message ?? null, method, uri, context: context ?? null };
        failures.push(failure);
        logFailure(failure);
    }

    //resource provider namespace (lowercase) -> registration state, from the providers call
    const registration = {};

    //what a failed call means, from its status and the registration of the resource provider it went to
    function failureHint(failure) {
        const namespace = /\/providers\/([^/?]+)\//i.exec(failure.uri ?? '')?.[1];
        const state = namespace ? registration[namespace.toLowerCase()] : null;
        if (state && state !== 'Registered') { return `resource provider ${namespace} is ${state} on this subscription`; }
        const code = failure.statusCode;
        if (code === 0) { return 'the call did not reach Azure (network error)'; }
        if (code === 401) { return 'the sign-in was not accepted for this call'; }
        if (code === 403) { return 'access denied: the account cannot read this, or a policy blocks it'; }
        if (code === 404) { return 'not found on this subscription'; }
        if (code === 429) { return 'throttled by Azure'; }
        if (code >= 500 && /AccessDenied|AuthorizationFailed|Forbidden/i.test(failure.message ?? '')) { return 'access denied: the account cannot read this, or a policy blocks it'; }
        if (code >= 500) { return 'an error on the Azure side'; }
        return null;
    }

    function describeFailure(failure) {
        const code = failure.statusCode === 0 ? 'network error' : `HTTP ${failure.statusCode}${failure.errorCode ? ` ${failure.errorCode}` : ''}`;
        const hint = failureHint(failure);
        const message = failure.message ? ` Azure: ${String(failure.message).split(/\r?\n/)[0].slice(0, 300)}` : '';
        return `${code}${hint ? `, ${hint}` : ''}.${message}`;
    }

    //every unexpected failure in the log, up to a limit; failures.json of the ingestion has all of them
    const LOGGED_FAILURES = 40;
    function logFailure(failure) {
        if (failures.length > LOGGED_FAILURES) { return; }
        log(`Could not read ${failure.context ?? failure.uri}: ${describeFailure(failure)}`);
        if (failures.length === LOGGED_FAILURES) { log('More requests failed; the ingestion zip lists all of them in failures.json.'); }
    }

    //Get-JsonProperty: one property, matched exactly first and then case-insensitively
    function field(value, name) {
        if (value === null || typeof value !== 'object' || Array.isArray(value)) { return null; }
        if (Object.prototype.hasOwnProperty.call(value, name)) { return value[name] ?? null; }
        const lower = name.toLowerCase();
        const key = Object.keys(value).find(k => k.toLowerCase() === lower);
        return key === undefined ? null : (value[key] ?? null);
    }

    //Get-JsonProp: a dotted path of properties
    function prop(value, path) {
        let current = value;
        for (const segment of path.split('.')) {
            current = field(current, segment);
            if (current === null) { return null; }
        }
        return current;
    }

    //Invoke-AzRest: one call with retries on throttling and transient errors; never throws on HTTP errors
    async function rest(uri, { resource = 'Arm', method = 'GET', body, context, expectedStatus = [], maxTransientRetries = 5 } = {}) {
        if (!/^https?:\/\//.test(uri)) { uri = endpoints[resource] + uri; }
        let attempt = 0, statusCode = 0, content = null, retryAfter = null;
        while (true) {
            signal?.throwIfAborted();
            attempt++;
            statusCode = 0; content = null; retryAfter = null;
            try {
                const headers = { Authorization: `Bearer ${await getToken(resource)}`, 'Accept-Language': 'en-US' };
                if (method !== 'GET') { headers['Content-Type'] = 'application/json; charset=utf-8'; }
                const response = await fetch(uri, { method, headers, body: method !== 'GET' ? (body ?? '') : undefined, signal });
                statusCode = response.status;
                content = await response.text();
                retryAfter = response.headers.get('Retry-After');
            } catch (e) {
                if (e?.name === 'AbortError') { throw e; }
                content = e?.message ?? String(e);
            }
            //a server error that denies access is final (Resource Graph backed endpoints answer 502 with AccessDenied details)
            const transient = (statusCode === 0 || statusCode === 408 || statusCode >= 500) && !DENIED.test(content ?? '');
            if ((statusCode === 429 && attempt <= 6) || (transient && attempt <= maxTransientRetries)) {
                let delay = Math.pow(2, attempt);
                const seconds = parseInt(retryAfter ?? '', 10);
                if (!Number.isNaN(seconds)) { delay = Math.max(1, Math.min(120, seconds)); }
                await sleep(delay * 1000, signal);
                continue;
            }
            break;
        }
        let json = null;
        if (content && /^\s*[{[]/.test(content)) { try { json = parseJson(content, { dateKind: 'String' }); } catch { json = null; } }
        const result = { uri, statusCode, json, text: json === null ? (content ?? '') : null, errorCode: null, errorMessage: null };
        if (statusCode < 200 || statusCode >= 300) {
            result.errorCode = prop(json, 'error.code');
            result.errorMessage = prop(json, 'error.message');
            for (const detail of (Array.isArray(prop(json, 'error.details')) ? prop(json, 'error.details') : [])) {
                result.errorMessage = (result.errorMessage ?? '') + ` | ${prop(detail, 'code')}: ${prop(detail, 'message')}`;
            }
            if (!result.errorMessage) { result.errorMessage = content ?? ''; }
            if (!expectedStatus.includes(statusCode)) { addFailure(uri, method, statusCode, result.errorCode, result.errorMessage, context); }
        }
        return result;
    }

    const ok = r => r.statusCode >= 200 && r.statusCode < 300;

    //Invoke-AzPaged: follows nextLink paging; a non collection response is returned in single
    async function paged(uri, { resource = 'Arm', method = 'GET', body, context, expectedStatus = [], maxTransientRetries = 5, seenIds = null, idProperty = 'id', onItem = null } = {}) {
        const result = { statusCode: 0, errorCode: null, isCollection: false, items: [], single: null, count: 0, duplicates: 0, complete: true };
        let next = uri, page = 0;
        while (next) {
            page++;
            const response = await rest(next, { resource, method, body, context, expectedStatus, maxTransientRetries });
            if (!ok(response)) {
                if (page === 1) { result.statusCode = response.statusCode; result.errorCode = response.errorCode; } else { result.complete = false; }
                break;
            }
            if (page === 1) { result.statusCode = response.statusCode; }
            const value = prop(response.json, 'value');
            if (Array.isArray(value)) {
                result.isCollection = true;
                for (const item of value) {
                    if (seenIds) {
                        const id = field(item, idProperty);
                        if (id) { if (seenIds.has(id)) { result.duplicates++; continue; } seenIds.add(id); }
                    }
                    if (onItem) { onItem(item); } else { result.items.push(item); }
                    result.count++;
                }
            } else {
                if (page === 1) { result.single = response.json; }
                break;
            }
            next = null;
            for (const name of ['nextLink', '@odata.nextLink', 'odata.nextLink']) {
                const link = field(response.json, name);
                if (typeof link === 'string' && link) { next = link; break; }
            }
        }
        return result;
    }

    //Find-PrincipalIds
    function findPrincipalIds(values, target) {
        for (const value of values) {
            if (value === null || value === undefined || typeof value !== 'object') { continue; }
            const text = JSON.stringify(value);
            for (const m of text.matchAll(PRINCIPAL_PROPERTY)) {
                for (const g of m[1].matchAll(GUID)) {
                    if (g[0] !== '00000000-0000-0000-0000-000000000000') { target.add(g[0].toLowerCase()); }
                }
            }
        }
    }

    //#endregion

    //#region per resource collection

    let apiVersions = {};

    //Get-ChildResource
    async function childResource(parentId, parentType, path, apiVersion, cache, itemFailures) {
        //'a/*': collection a with every item read in full; null when the listing or one of the items failed
        if (path.endsWith('/*')) {
            const collection = path.slice(0, -2);
            if (!apiVersion) {
                let candidates = apiVersions[`${parentType}/${childTypeSegments(collection)}`.toLowerCase()];
                if (!candidates || !candidates.length) { candidates = apiVersions[parentType.toLowerCase()]; }
                apiVersion = candidates?.[0] ?? '';
            }
            const listed = await childResource(parentId, parentType, collection, apiVersion, cache, itemFailures);
            if (listed === null) { return null; }
            const full = [];
            for (const item of (Array.isArray(listed) ? listed : [listed])) {
                const itemId = prop(item, 'id');
                if (!itemId) { continue; }
                const response = await rest(`${itemId}?api-version=${apiVersion}`, { context: parentId, expectedStatus: [400, 404, 405, 409], maxTransientRetries: 1 });
                if (!ok(response)) {
                    itemFailures.push({ path: itemId, apiVersion, statusCode: response.statusCode, errorCode: response.errorCode });
                    return null;
                }
                full.push(response.json);
            }
            return full;
        }
        const star = path.indexOf('/*/');
        if (star > 0) {
            const prefix = path.slice(0, star), rest2 = path.slice(star + 3);
            const parents = await childResource(parentId, parentType, prefix, apiVersion, cache, itemFailures);
            const combined = [];
            if (parents === null) { return combined; }
            const childParentType = `${parentType}/${childTypeSegments(prefix)}`;
            for (const parent of (Array.isArray(parents) ? parents : [parents])) {
                const parentItemId = prop(parent, 'id');
                if (!parentItemId) { continue; }
                const children = await childResource(parentItemId, childParentType, rest2, apiVersion, cache, itemFailures);
                if (Array.isArray(children)) { combined.push(...children); } else if (children !== null) { combined.push(children); }
            }
            return combined;
        }
        const cacheKey = `${parentId}/${path}`.toLowerCase();
        if (Object.prototype.hasOwnProperty.call(cache, cacheKey)) { return cache[cacheKey]; }
        if (!apiVersion) {
            let candidates = apiVersions[`${parentType}/${childTypeSegments(path)}`.toLowerCase()];
            if (!candidates || !candidates.length) { candidates = apiVersions[parentType.toLowerCase()]; }
            apiVersion = candidates?.[0] ?? '';
        }
        const separator = path.includes('?') ? '&' : '?';
        const result = await paged(`${parentId}/${path}${separator}api-version=${apiVersion}`, { context: parentId, expectedStatus: [400, 404, 405, 409], maxTransientRetries: 1 });
        let value = null;
        if (ok(result)) { value = result.isCollection ? result.items : result.single; }
        else { itemFailures.push({ path: `${parentId}/${path}`, apiVersion, statusCode: result.statusCode, errorCode: result.errorCode }); }
        cache[cacheKey] = value;
        return value;
    }

    //Export-ResourceDetail
    async function exportResource(item) {
        const typeKey = item.type.toLowerCase();
        const itemFailures = [];
        const record = { id: item.id, type: item.type, apiVersion: null, collectedAt: isoNow(), resource: null, diagnosticSettings: null, children: {}, textContent: {}, failures: itemFailures };
        const candidates = apiVersions[typeKey] ?? [];
        if (!candidates.length || !candidates[0]) { itemFailures.push({ path: item.id, apiVersion: null, statusCode: 0, errorCode: 'NoApiVersionForType' }); }
        const expand = plan.resourceExpandMap[typeKey];
        for (const apiVersion of candidates) {
            if (!apiVersion) { continue; }
            const response = await rest(`${item.id}?api-version=${apiVersion}${expand ? '&' + expand : ''}`, { context: item.id });
            if (ok(response)) { record.resource = response.json; record.apiVersion = apiVersion; break; }
            itemFailures.push({ path: item.id, apiVersion, statusCode: response.statusCode, errorCode: response.errorCode });
            if (response.statusCode !== 400) { break; }
        }
        if (record.resource !== null) {
            if (item.type.split('/').length === 2 || plan.diagnosticSettingsChildTypes.includes(typeKey)) {
                const diagnostics = await paged(`${item.id}/providers/Microsoft.Insights/diagnosticSettings?api-version=${core.diagnosticSettings}`, { context: item.id, expectedStatus: [400, 404, 405, 409], maxTransientRetries: 1 });
                if (ok(diagnostics)) { record.diagnosticSettings = diagnostics.items; }
                else { itemFailures.push({ path: `${item.id}/providers/Microsoft.Insights/diagnosticSettings`, apiVersion: core.diagnosticSettings, statusCode: diagnostics.statusCode, errorCode: diagnostics.errorCode }); }
            }
            const cache = {};
            for (const entry of (plan.childResourceMap[typeKey] ?? [])) {
                const at = entry.indexOf('@');
                const path = at < 0 ? entry : entry.slice(0, at);
                const pinned = at < 0 ? null : entry.slice(at + 1);
                //the master database does not support data masking or classification and answers with a 500
                if (typeKey === 'microsoft.sql/servers/databases' && /\/databases\/master$/i.test(item.id) && /^(dataMaskingPolicies|currentSensitivityLabels)/i.test(path)) { continue; }
                record.children[path] = await childResource(item.id, item.type, path, pinned, cache, itemFailures);
            }
            //Logic App (Standard): workflows, connections.json and the versions of each workflow
            const workflowApp = typeKey === 'microsoft.web/sites' && /workflowapp/i.test(String(prop(record.resource, 'kind') ?? ''));
            if (workflowApp) {
                for (const entry of plan.workflowAppChildren) {
                    const at = entry.indexOf('@');
                    const path = at < 0 ? entry : entry.slice(0, at);
                    const pinned = at < 0 ? null : entry.slice(at + 1);
                    record.children[path] = await childResource(item.id, item.type, path, pinned, cache, itemFailures);
                }
                const at = plan.workflowAppVersionsPath.indexOf('@');
                const versionsPath = plan.workflowAppVersionsPath.slice(0, at);
                const versionsApi = plan.workflowAppVersionsPath.slice(at + 1);
                const versions = {};
                for (const workflow of (record.children['workflows/*'] ?? [])) {
                    const name = String(prop(workflow, 'name') ?? '').replace(/^.*\//, '');
                    if (name) { versions[name] = await childResource(item.id, item.type, versionsPath.replace('{name}', encodeURIComponent(name).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())), versionsApi, cache, itemFailures); }
                }
                record.children.workflowVersions = versions;
            }
            for (const path of (plan.textContentMap[typeKey] ?? [])) {
                const response = await rest(`${item.id}/${path}?api-version=${record.apiVersion}`, { context: item.id, expectedStatus: [400, 404], maxTransientRetries: 1 });
                if (ok(response)) { record.textContent[path] = response.json !== null ? JSON.stringify(response.json) : response.text; }
                else { itemFailures.push({ path: `${item.id}/${path}`, apiVersion: record.apiVersion, statusCode: response.statusCode, errorCode: response.errorCode }); }
            }
            //metric queries: 'names' or 'names|dimension filter'
            const metricSpecs = [...[plan.resourceMetricsMap[typeKey]].flat(), ...(workflowApp ? plan.workflowAppMetrics : [])].filter(Boolean);
            if (metricSpecs.length) {
                //all windows or nothing, so that totals are never computed from part of the period
                const path = 'providers/Microsoft.Insights/metrics';
                let windows = [];
                for (const spec of metricSpecs) {
                    const bar = spec.indexOf('|');
                    const metricNames = bar < 0 ? spec : spec.slice(0, bar);
                    const filterQuery = bar < 0 ? '' : `&$filter=${encodeURIComponent(spec.slice(bar + 1)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())}`;
                    for (const timespan of metricsTimespans) {
                        const response = await rest(`${item.id}/${path}?metricnames=${metricNames}&aggregation=Total&interval=P1D&timespan=${timespan}${filterQuery}&api-version=${core.metrics}`, { context: item.id, expectedStatus: [400, 404], maxTransientRetries: 1 });
                        if (!ok(response)) {
                            windows = null;
                            itemFailures.push({ path: `${item.id}/${path}`, apiVersion: core.metrics, statusCode: response.statusCode, errorCode: response.errorCode });
                            break;
                        }
                        windows.push(response.json);
                    }
                    if (windows === null) { break; }
                }
                record.children.metrics = windows;
            }
        }
        write(item.file, record);
        const ids = new Set();
        findPrincipalIds([record.resource], ids);
        for (const child of Object.values(record.children)) { findPrincipalIds(Array.isArray(child) ? child : [child], ids); }
        //the connector of an API connection, whose metadata is collected after the resources
        const managedApiId = typeKey === 'microsoft.web/connections' ? prop(record.resource, 'properties.api.id') : null;
        //resources the analysis follows, which may be in another subscription: the data collection rules of a machine, the
        //networks a virtual network is peered with and the action groups of an activity log alert
        const referencedIds = [];
        if (typeKey === 'microsoft.insights/activitylogalerts') {
            const groups = prop(record.resource, 'properties.actions.actionGroups');
            for (const group of (Array.isArray(groups) ? groups : [])) {
                const groupId = field(group, 'actionGroupId');
                if (groupId) { referencedIds.push(String(groupId)); }
            }
        }
        const associations = record.children['providers/Microsoft.Insights/dataCollectionRuleAssociations'];
        for (const association of (Array.isArray(associations) ? associations : [associations])) {
            const ruleId = prop(association, 'properties.dataCollectionRuleId');
            if (ruleId) { referencedIds.push(String(ruleId)); }
        }
        const peerings = prop(record.resource, 'properties.virtualNetworkPeerings');
        for (const peering of (Array.isArray(peerings) ? peerings : [])) {
            const remoteId = prop(peering, 'properties.remoteVirtualNetwork.id');
            if (remoteId) { referencedIds.push(String(remoteId)); }
        }
        return { id: item.id, type: item.type, file: item.file, apiVersion: record.apiVersion, status: record.resource !== null ? 'ok' : 'failed', failureCount: itemFailures.length, principalIds: [...ids], managedApiId, referencedIds };
    }

    //Export-ResourceGroupDetail
    async function exportResourceGroup(item) {
        const itemFailures = [];
        const record = { id: item.id, collectedAt: isoNow() };
        for (const [name, path, apiVersion] of plan.resourceGroupEndpoints) {
            const separator = path.includes('?') ? '&' : '?';
            const result = await paged(`${item.id}/${path}${separator}api-version=${apiVersion}`, { context: item.id, expectedStatus: [400, 404] });
            if (ok(result)) { record[name] = result.items; }
            else {
                record[name] = null;
                itemFailures.push({ path: `${item.id}/${path}`, apiVersion, statusCode: result.statusCode, errorCode: result.errorCode });
            }
        }
        record.failures = itemFailures;
        write(item.file, record);
        return { id: item.id, type: 'resourceGroup', file: item.file, apiVersion: null, status: 'ok', failureCount: itemFailures.length, principalIds: [] };
    }

    //#endregion

    //#region subscription level, Resource Graph and Graph exports

    //Export-Endpoint
    async function exportEndpoint(uri, relative, { method = 'GET', resource = 'Arm', principalTarget = null } = {}) {
        const started = Date.now();
        const result = await paged(uri, { method, resource, context: relative });
        const seconds = Math.round((Date.now() - started) / 100) / 10;
        if (!ok(result)) { return { status: 'failed', statusCode: result.statusCode, errorCode: result.errorCode, seconds }; }
        const value = result.isCollection ? result.items : (result.single !== null ? result.single : []);
        write(relative, value);
        if (principalTarget) { findPrincipalIds(Array.isArray(value) ? value : [value], principalTarget); }
        return { status: result.complete ? 'ok' : 'partial', count: result.isCollection ? result.count : 1, seconds };
    }

    //Export-ResourceGraphTable
    async function exportResourceGraphTable(table, relative) {
        const options = { resultFormat: 'objectArray', $top: 1000 };
        const rows = [];
        let status = { status: 'ok', count: 0 };
        while (true) {
            const body = JSON.stringify({ subscriptions: [subscriptionId], query: table, options });
            const response = await rest(`/providers/Microsoft.ResourceGraph/resources?api-version=${core.resourceGraph}`, { method: 'POST', body, context: `resourceGraph/${table}`, expectedStatus: [400] });
            if (!ok(response)) {
                status = { status: rows.length > 0 ? 'partial' : 'unavailable', statusCode: response.statusCode, errorCode: response.errorCode, message: response.errorMessage };
                break;
            }
            const data = prop(response.json, 'data');
            if (Array.isArray(data)) { rows.push(...data); }
            const skipToken = prop(response.json, '$skipToken');
            if (!skipToken) { break; }
            options.$skipToken = skipToken;
        }
        status.count = rows.length;
        if (status.status !== 'unavailable') { write(relative, rows); }
        return status;
    }

    //Invoke-GraphBatch: relative Graph v1.0 GET requests through $batch, 20 per call, including paging
    //Invoke-GraphBatch; version 'beta' for what v1.0 does not return (service principals as members or owners of groups)
    async function graphBatch(requests, expectedStatus = [], version = 'v1.0') {
        const results = new Map();
        const attempts = new Map();
        const pending = [...requests.keys()];
        while (pending.length) {
            const batchKeys = pending.splice(0, 20);
            const body = JSON.stringify({ requests: batchKeys.map((key, i) => ({ id: String(i), method: 'GET', url: requests.get(key) })) });
            const response = await rest(`/${version}/$batch`, { resource: 'Graph', method: 'POST', body, context: 'graph batch' });
            if (!ok(response)) {
                for (const key of batchKeys) { results.set(key, { statusCode: response.statusCode, errorCode: response.errorCode, items: null, single: null }); }
                continue;
            }
            let delay = 0;
            for (const item of (prop(response.json, 'responses') ?? [])) {
                const key = batchKeys[Number(prop(item, 'id'))];
                const status = Number(prop(item, 'status'));
                const itemBody = prop(item, 'body');
                if ((status === 429 || status >= 500) && (attempts.get(key) ?? 0) < 5) {
                    attempts.set(key, (attempts.get(key) ?? 0) + 1);
                    let retryAfter = parseInt(String(field(field(item, 'headers'), 'Retry-After') ?? ''), 10);
                    if (Number.isNaN(retryAfter)) { retryAfter = 5; }
                    delay = Math.max(delay, Math.min(120, retryAfter));
                    pending.push(key);
                    continue;
                }
                const result = { statusCode: status, errorCode: null, items: null, single: null };
                if (status >= 200 && status < 300) {
                    const value = prop(itemBody, 'value');
                    if (Array.isArray(value)) {
                        result.items = value.slice();
                        const nextLink = field(itemBody, '@odata.nextLink');
                        if (nextLink) {
                            const more = await paged(nextLink, { resource: 'Graph', context: requests.get(key) });
                            if (ok(more)) { result.items.push(...more.items); }
                        }
                    } else {
                        result.single = itemBody;
                    }
                } else {
                    result.errorCode = prop(itemBody, 'error.code');
                    if (!expectedStatus.includes(status)) { addFailure(`${endpoints.Graph}/${version}${requests.get(key)}`, 'GET', status, result.errorCode, prop(itemBody, 'error.message'), 'graph batch item'); }
                }
                results.set(key, result);
            }
            if (delay > 0) { await sleep(delay * 1000, signal); }
        }
        return results;
    }

    //Get-DirectoryObjectsByIds
    async function directoryObjectsByIds(ids) {
        const lookup = { objects: [], failed: false };
        for (let i = 0; i < ids.length; i += 1000) {
            const body = JSON.stringify({ ids: ids.slice(i, i + 1000) });
            const result = await paged('/v1.0/directoryObjects/getByIds', { resource: 'Graph', method: 'POST', body, context: 'directoryObjects/getByIds' });
            if (ok(result)) { lookup.objects.push(...result.items); } else { lookup.failed = true; }
        }
        return lookup;
    }

    //Export-EntraData
    async function exportEntraData(principalIdSet) {
        const out = {};
        const directoryObjects = [];
        const objectsById = new Map();
        const userIds = new Set(), groupIds = new Set(), servicePrincipalIds = new Set();
        out.organization = await exportEndpoint('/v1.0/organization', 'identity/organization.json', { resource: 'Graph' });
        const addObjects = objects => {
            for (const object of objects) {
                const id = prop(object, 'id');
                if (!id || objectsById.has(id)) { continue; }
                objectsById.set(id, object);
                directoryObjects.push(object);
                switch (field(object, '@odata.type')) {
                    case '#microsoft.graph.user': userIds.add(id); break;
                    case '#microsoft.graph.group': groupIds.add(id); break;
                    case '#microsoft.graph.servicePrincipal': servicePrincipalIds.add(id); break;
                    default: break;
                }
            }
        };
        let lookupFailed = false;
        if (principalIdSet.size > 0) {
            const lookup = await directoryObjectsByIds([...principalIdSet]);
            lookupFailed = lookup.failed;
            addObjects(lookup.objects);
        }

        //Get-GroupEligibleMembers: eligible members of PIM for Groups per group id, added to the cache: members (users with the
        //member properties, service principals, the transitive members of eligible groups) and error (status code when
        //they could not all be read)
        const eligibleMembers = new Map();
        const groupEligibleMembers = async ids => {
            const missing = ids.filter(id => id && !eligibleMembers.has(id));
            if (!missing.length) { return; }
            const requests = new Map(missing.map(id => [id, `/identityGovernance/privilegedAccess/group/eligibilitySchedules?$filter=${encodeURIComponent(`groupId eq '${id}' and accessId eq 'member'`).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())}&$expand=principal`]));
            //400 ResourceTypeNotSupported: a group PIM cannot manage (synchronized from on-premises), so without eligible members
            const schedules = await graphBatch(requests, [400]);
            //the principal expansion has default properties only, so users and groups are read again
            const principalRequests = new Map();
            for (const id of missing) {
                for (const schedule of (schedules.get(id)?.items ?? [])) {
                    const principalId = prop(schedule, 'principalId');
                    const type = field(field(schedule, 'principal'), '@odata.type');
                    if (type === '#microsoft.graph.user') { principalRequests.set(`user|${principalId}`, `/users/${principalId}?$select=${plan.graphSelect.member}`); }
                    if (type === '#microsoft.graph.group') { principalRequests.set(`group|${principalId}`, `/groups/${principalId}/transitiveMembers?$select=${plan.graphSelect.member}&$top=999`); }
                }
            }
            const principalResults = principalRequests.size ? await graphBatch(principalRequests, [404]) : new Map();
            for (const id of missing) {
                const result = schedules.get(id);
                if (result.statusCode === 400 && result.errorCode === 'ResourceTypeNotSupported') { eligibleMembers.set(id, { members: [], error: null }); continue; }
                if (result.statusCode >= 300) { eligibleMembers.set(id, { members: null, error: result.statusCode }); continue; }
                const members = [];
                const seen = new Set();
                let failed = null;
                for (const schedule of (result.items ?? [])) {
                    const principalId = prop(schedule, 'principalId');
                    const type = field(field(schedule, 'principal'), '@odata.type');
                    let found = [];
                    if (type === '#microsoft.graph.user' || type === '#microsoft.graph.group') {
                        const detail = principalResults.get(`${type === '#microsoft.graph.user' ? 'user' : 'group'}|${principalId}`);
                        if (detail && detail.statusCode >= 300 && detail.statusCode !== 404) { failed = detail.statusCode; }
                        if (detail?.single != null) { found = [detail.single]; } else if (detail?.items) { found = detail.items; }
                    } else if (field(schedule, 'principal')) {
                        found = [field(schedule, 'principal')];
                    }
                    for (const member of found) { const memberId = String(prop(member, 'id')); if (!seen.has(memberId)) { seen.add(memberId); members.push(member); } }
                }
                eligibleMembers.set(id, { members, error: failed });
            }
        };

        //Get-GroupServicePrincipals: service principals that are transitive members or owners of groups, per group id, added
        //to the cache. Graph v1.0 leaves service principals out of group members and owners; beta returns them
        const groupServicePrincipals = new Map();
        const readGroupServicePrincipals = async ids => {
            const missing = ids.filter(id => id && !groupServicePrincipals.has(id));
            if (!missing.length) { return; }
            const requests = new Map();
            for (const id of missing) {
                requests.set(`members|${id}`, `/groups/${id}/transitiveMembers/microsoft.graph.servicePrincipal?$select=${plan.graphSelect.member}&$top=999`);
                requests.set(`owners|${id}`, `/groups/${id}/owners/microsoft.graph.servicePrincipal?$select=${plan.graphSelect.member}`);
            }
            const results = await graphBatch(requests, [404], 'beta');
            for (const id of missing) {
                const members = results.get(`members|${id}`);
                const owners = results.get(`owners|${id}`);
                groupServicePrincipals.set(id, {
                    members: members?.items ?? null, membersError: members && members.statusCode >= 300 ? members.statusCode : null,
                    owners: owners?.items ?? null, ownersError: owners && owners.statusCode >= 300 ? owners.statusCode : null
                });
            }
        };

        log(`Graph: ${groupIds.size} groups`);
        const memberSelect = `$select=${plan.graphSelect.member}`;
        const groupRequests = new Map();
        for (const id of groupIds) {
            groupRequests.set(`members|${id}`, `/groups/${id}/transitiveMembers?${memberSelect}&$top=999`);
            groupRequests.set(`owners|${id}`, `/groups/${id}/owners?${memberSelect}`);
            groupRequests.set(`properties|${id}`, `/groups/${id}?$select=${plan.graphSelect.group}`);
        }
        const groupResults = groupRequests.size ? await graphBatch(groupRequests) : new Map();
        await groupEligibleMembers([...groupIds]);
        await readGroupServicePrincipals([...groupIds]);
        const groupRecords = [];
        const additionalIds = new Set();
        for (const id of [...groupIds]) {
            const members = groupResults.get(`members|${id}`);
            const owners = groupResults.get(`owners|${id}`);
            const eligible = eligibleMembers.get(id);
            const servicePrincipals = groupServicePrincipals.get(id);
            for (const related of [...(members?.items ?? []), ...(owners?.items ?? []), ...(eligible?.members ?? []), ...(servicePrincipals?.members ?? []), ...(servicePrincipals?.owners ?? [])]) {
                const relatedId = prop(related, 'id');
                switch (field(related, '@odata.type')) {
                    case '#microsoft.graph.user': userIds.add(relatedId); break;
                    case '#microsoft.graph.servicePrincipal': if (!objectsById.has(relatedId)) { additionalIds.add(relatedId); } break;
                    default: break;
                }
            }
            groupRecords.push({ id, transitiveMembers: members?.items ?? null, transitiveMembersError: members && members.statusCode >= 300 ? members.statusCode : null, eligibleMembers: eligible?.members ?? null, eligibleMembersError: eligible?.error ?? null, servicePrincipalMembers: servicePrincipals?.members ?? null, servicePrincipalMembersError: servicePrincipals?.membersError ?? null, owners: owners?.items ?? null, servicePrincipalOwners: servicePrincipals?.owners ?? null, servicePrincipalOwnersError: servicePrincipals?.ownersError ?? null, properties: groupResults.get(`properties|${id}`)?.single ?? null });
        }
        write('identity/groups.json', groupRecords);
        out.groups = { status: 'ok', count: groupRecords.length };
        if (additionalIds.size > 0) {
            const lookup = await directoryObjectsByIds([...additionalIds]);
            lookupFailed = lookupFailed || lookup.failed;
            addObjects(lookup.objects);
        }

        const unresolved = [...principalIdSet].filter(id => !objectsById.has(id));
        write('identity/directoryObjects.json', directoryObjects);
        write('identity/unresolvedPrincipalIds.json', unresolved);
        const deletedPrincipals = [];
        if (unresolved.length > 0 && !lookupFailed) {
            const deletedRequests = new Map(unresolved.map(id => [id, `/directory/deletedItems/${id}`]));
            for (const result of (await graphBatch(deletedRequests, [404])).values()) { if (result.single !== null) { deletedPrincipals.push(result.single); } }
        }
        write('identity/deletedPrincipals.json', deletedPrincipals);
        out.deletedPrincipals = { status: 'ok', count: deletedPrincipals.length };
        out.directoryObjects = { status: lookupFailed ? 'failed' : 'ok', count: directoryObjects.length, unresolved: unresolved.length };

        log(`Graph: ${userIds.size} users`);
        let userSelect = plan.graphSelect.user;
        const userIdList = [...userIds];
        let signInActivity = false;
        if (userIdList.length > 0) {
            const probe = await rest(`/v1.0/users/${userIdList[0]}?$select=id,signInActivity`, { resource: 'Graph', context: 'signInActivity probe', expectedStatus: [400, 403, 404] });
            if (ok(probe)) { signInActivity = true; userSelect += ',signInActivity'; }
        }
        const userRequests = new Map();
        for (let i = 0; i < userIdList.length; i += 15) {
            const filter = `id in ('${userIdList.slice(i, i + 15).join("','")}')`;
            userRequests.set(`users|${i}`, `/users?$filter=${encodeURIComponent(filter).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())}&$select=${userSelect}`);
        }
        const users = [];
        if (userRequests.size) { for (const result of (await graphBatch(userRequests)).values()) { if (result.items) { users.push(...result.items); } } }
        write('identity/users.json', users);
        out.users = { status: 'ok', count: users.length, signInActivity };

        log(`Graph: ${servicePrincipalIds.size} service principals`);
        const tenant = tokenClaims(await getToken('Graph')).tid;
        const spRequests = new Map();
        for (const id of servicePrincipalIds) {
            spRequests.set(`appRoleAssignments|${id}`, `/servicePrincipals/${id}/appRoleAssignments`);
            spRequests.set(`oauth2PermissionGrants|${id}`, `/servicePrincipals/${id}/oauth2PermissionGrants`);
            spRequests.set(`owners|${id}`, `/servicePrincipals/${id}/owners?$select=${plan.graphSelect.owner}`);
            const servicePrincipal = objectsById.get(id);
            const appId = prop(servicePrincipal, 'appId');
            if (prop(servicePrincipal, 'servicePrincipalType') === 'Application' && prop(servicePrincipal, 'appOwnerOrganizationId') === tenant && appId) {
                spRequests.set(`application|${id}`, `/applications(appId='${appId}')`);
            }
        }
        const spResults = spRequests.size ? await graphBatch(spRequests) : new Map();
        const appRequests = new Map();
        for (const id of servicePrincipalIds) {
            const application = spResults.get(`application|${id}`)?.single ?? null;
            const applicationObjectId = prop(application, 'id');
            if (applicationObjectId) {
                appRequests.set(`owners|${id}`, `/applications/${applicationObjectId}/owners?$select=${plan.graphSelect.owner}`);
                appRequests.set(`federatedIdentityCredentials|${id}`, `/applications/${applicationObjectId}/federatedIdentityCredentials`);
            }
        }
        const appResults = appRequests.size ? await graphBatch(appRequests) : new Map();
        const apiIds = new Set();
        const spRecords = [];
        for (const id of servicePrincipalIds) {
            const appRoleAssignments = spResults.get(`appRoleAssignments|${id}`)?.items ?? null;
            const grants = spResults.get(`oauth2PermissionGrants|${id}`)?.items ?? null;
            for (const assignment of [...(appRoleAssignments ?? []), ...(grants ?? [])]) {
                const apiId = prop(assignment, 'resourceId');
                if (apiId) { apiIds.add(apiId); }
            }
            spRecords.push({
                id,
                appRoleAssignments,
                oauth2PermissionGrants: grants,
                owners: spResults.get(`owners|${id}`)?.items ?? null,
                application: spResults.get(`application|${id}`)?.single ?? null,
                applicationOwners: appResults.get(`owners|${id}`)?.items ?? null,
                applicationFederatedIdentityCredentials: appResults.get(`federatedIdentityCredentials|${id}`)?.items ?? null
            });
        }
        write('identity/servicePrincipals.json', spRecords);
        out.servicePrincipals = { status: 'ok', count: spRecords.length };

        const apiRequests = new Map([...apiIds].map(apiId => [apiId, `/servicePrincipals/${apiId}?$select=${plan.graphSelect.api}`]));
        const apis = [];
        if (apiRequests.size) { for (const result of (await graphBatch(apiRequests)).values()) { if (result.single !== null) { apis.push(result.single); } } }
        write('identity/apiServicePrincipals.json', apis);
        out.apiServicePrincipals = { status: 'ok', count: apis.length };

        for (const [name, uri] of plan.graphDirectoryExports) {
            out[name] = await exportEndpoint(uri, `identity/${name}.json`, { resource: 'Graph' });
        }

        //users and groups that hold directory roles: the user properties (the principal expansion of role eligibilities has
        //no userType or onPremisesSyncEnabled) and the transitive members of the groups
        const rolePrincipalTypes = new Map();
        for (const name of ['directoryRoleAssignments', 'directoryRoleEligibilitySchedules']) {
            if (!['ok', 'partial'].includes(out[name]?.status)) { continue; }
            for (const item of vfs.entry(`${root}/identity/${name}.json`)?.value ?? []) {
                const type = field(field(item, 'principal'), '@odata.type');
                const principalId = field(item, 'principalId');
                if (principalId && ['#microsoft.graph.user', '#microsoft.graph.group'].includes(type)) { rolePrincipalTypes.set(String(principalId), type); }
            }
        }
        const roleRequests = new Map([...rolePrincipalTypes].map(([id, type]) => [id, type === '#microsoft.graph.user' ? `/users/${id}?$select=${plan.graphSelect.member}` : `/groups/${id}/transitiveMembers?$select=${plan.graphSelect.member}&$top=999`]));
        const roleResults = roleRequests.size ? await graphBatch(roleRequests, [404]) : new Map();
        const roleGroupIds = [...rolePrincipalTypes].filter(([, type]) => type === '#microsoft.graph.group').map(([id]) => id);
        await groupEligibleMembers(roleGroupIds);
        await readGroupServicePrincipals(roleGroupIds);
        const rolePrincipals = [...rolePrincipalTypes].map(([id, type]) => {
            const result = roleResults.get(id);
            const eligible = type === '#microsoft.graph.group' ? eligibleMembers.get(id) : null;
            const servicePrincipals = type === '#microsoft.graph.group' ? groupServicePrincipals.get(id) : null;
            return { id, type, user: result?.single ?? null, members: result?.items ?? null, error: result && result.statusCode >= 300 ? result.statusCode : null, eligibleMembers: eligible?.members ?? null, eligibleMembersError: eligible?.error ?? null, servicePrincipalMembers: servicePrincipals?.members ?? null, servicePrincipalMembersError: servicePrincipals?.membersError ?? null };
        });
        write('identity/directoryRolePrincipals.json', rolePrincipals);
        out.directoryRolePrincipals = { status: 'ok', count: rolePrincipals.length };

        //user members of the groups Conditional Access policies exclude, which is how emergency access accounts are usually excluded
        if (['ok', 'partial'].includes(out.conditionalAccessPolicies?.status)) {
            const policies = vfs.entry(`${root}/identity/conditionalAccessPolicies.json`)?.value ?? [];
            const excludedGroupIds = [...new Set(policies.flatMap(policy => prop(policy, 'conditions.users.excludeGroups') ?? []).filter(Boolean))].sort();
            const excludedRequests = new Map(excludedGroupIds.map(id => [id, `/groups/${id}/transitiveMembers/microsoft.graph.user?$select=${plan.graphSelect.member}&$top=999`]));
            //404: a deleted group that a policy still excludes
            const excludedResults = excludedRequests.size ? await graphBatch(excludedRequests, [404]) : new Map();
            const excludedGroups = excludedGroupIds.map(id => {
                const members = excludedResults.get(id);
                return { id, members: members?.items ?? null, membersError: members && members.statusCode >= 300 ? members.statusCode : null };
            });
            write('identity/conditionalAccessExcludedGroups.json', excludedGroups);
            out.conditionalAccessExcludedGroups = { status: 'ok', count: excludedGroups.length };
        }
        return out;
    }

    //#endregion

    //#region main

    try {
        log(`Authenticating (${authMethod})`);
        const armClaims = tokenClaims(await getToken('Arm'));
        tenantId = armClaims.tid;
        caller = { tenantId: armClaims.tid, objectId: armClaims.oid ?? null, appId: armClaims.appid ?? armClaims.azp ?? null, identityType: armClaims.idtyp ?? (armClaims.scp ? 'user' : 'app') };

        const subscriptionResponse = await rest(`/subscriptions/${subscriptionId}?api-version=${core.subscription}`, { context: 'subscription' });
        if (!ok(subscriptionResponse)) { throw new Error(`Cannot read subscription ${subscriptionId} (${subscriptionResponse.statusCode} ${subscriptionResponse.errorCode}): ${subscriptionResponse.errorMessage}`); }
        subscriptionInfo = subscriptionResponse.json;
        write('subscription/subscription.json', subscriptionInfo);
        log(`Subscription: ${prop(subscriptionInfo, 'displayName')} (${prop(subscriptionInfo, 'state')})`);

        //providers give the api versions for every resource type: latest two stable plus latest preview as fallbacks
        const providers = await paged(`/subscriptions/${subscriptionId}/providers?api-version=${core.providers}`, { context: 'providers' });
        if (!ok(providers)) { throw new Error(`Cannot list resource providers (${providers.statusCode} ${providers.errorCode})`); }
        write('subscription/providers.json', providers.items);
        apiVersions = {};
        const descending = (a, b) => a < b ? 1 : a > b ? -1 : 0;
        for (const provider of providers.items) {
            const namespace = prop(provider, 'namespace');
            if (namespace) { registration[String(namespace).toLowerCase()] = prop(provider, 'registrationState'); }
            for (const resourceType of (prop(provider, 'resourceTypes') ?? [])) {
                const versions = (prop(resourceType, 'apiVersions') ?? []).map(String);
                const stable = versions.filter(v => !/preview|alpha|beta/i.test(v)).sort(descending).slice(0, 2);
                const preview = versions.filter(v => /preview|alpha|beta/i.test(v)).sort(descending).slice(0, 1);
                apiVersions[`${namespace}/${prop(resourceType, 'resourceType')}`.toLowerCase()] = [...stable, ...preview];
            }
        }

        log('Subscription settings, RBAC, policy and Defender for Cloud');
        progress({ phase: 'subscription', done: 0, total: plan.subscriptionEndpoints.length });
        let done = 0;
        for (const [folderPart, name, path, apiVersion, method] of plan.subscriptionEndpoints) {
            const separator = path.includes('?') ? '&' : '?';
            const base = path.startsWith('/') ? path : `/subscriptions/${subscriptionId}/${path}`;
            sections[`${folderPart}/${name}`] = await exportEndpoint(`${base}${separator}api-version=${apiVersion}`, `${folderPart}/${name}.json`, { method: method ?? 'GET', principalTarget: principalIds });
            progress({ phase: 'subscription', done: ++done, total: plan.subscriptionEndpoints.length });
        }

        const resourceGroups = await paged(`/subscriptions/${subscriptionId}/resourcegroups?api-version=${core.resourceGroups}`, { context: 'resourceGroups' });
        const resources = await paged(`/subscriptions/${subscriptionId}/resources?$expand=${plan.resourceListExpand}&api-version=${core.resources}`, { context: 'resources' });
        if (!ok(resourceGroups) || !ok(resources)) { throw new Error('Cannot list resource groups or resources'); }
        write('subscription/resourceGroups.json', resourceGroups.items);
        write('subscription/resources.json', resources.items);
        counts.resourceGroups = resourceGroups.count;
        counts.resources = resources.count;

        const workItems = [];
        for (const resourceGroup of resourceGroups.items) {
            const id = prop(resourceGroup, 'id');
            workItems.push({ kind: 'ResourceGroup', id, type: 'Microsoft.Resources/resourceGroups', file: `resourceGroups/${await safeFileName(prop(resourceGroup, 'name'), id)}.json` });
        }
        for (const resource of resources.items) {
            const id = prop(resource, 'id');
            const type = prop(resource, 'type');
            const slash = type.indexOf('/');
            const namespace = type.slice(0, slash), typeName = type.slice(slash + 1);
            workItems.push({ kind: 'Resource', id, type, file: `resources/${namespace}/${typeName.replace(/\//g, '.')}/${await safeFileName(prop(resource, 'name'), id)}.json` });
        }

        log(`Collecting ${resourceGroups.count} resource groups and ${resources.count} resources (${throttleLimit} parallel)`);
        let itemsDone = 0;
        progress({ phase: 'resources', done: 0, total: workItems.length });
        const itemResults = await pool(workItems, throttleLimit, async item => {
            let result;
            try { result = item.kind === 'ResourceGroup' ? await exportResourceGroup(item) : await exportResource(item); }
            catch (e) {
                if (e?.name === 'AbortError') { throw e; }
                result = { id: item.id, type: item.type, file: null, apiVersion: null, status: `error: ${e?.message ?? e}`, failureCount: 0, principalIds: [] };
            }
            itemsDone++;
            if (itemsDone % 25 === 0 || itemsDone === workItems.length) { progress({ phase: 'resources', done: itemsDone, total: workItems.length }); }
            return result;
        }, signal);
        for (const r of itemResults) { for (const id of r.principalIds) { principalIds.add(id); } }
        write('index.json', itemResults.map(r => ({ id: r.id, type: r.type, file: r.file, apiVersion: r.apiVersion, status: r.status, failureCount: r.failureCount })));
        counts.itemsFailed = itemResults.filter(r => r.status !== 'ok').length;
        for (const r of itemResults.filter(x => x.status.startsWith('error:'))) { log(`${r.id}: ${r.status}`); }

        //connector metadata of the API connections: which connection parameters hold a secret. One call per connector
        const managedApiIds = [...new Set(itemResults.map(r => r.managedApiId).filter(id => typeof id === 'string' && id).map(id => id.toLowerCase()))].sort();
        log(`Connector metadata (${managedApiIds.length} connectors)`);
        const managedApis = [];
        let managedApisFailed = 0;
        for (const managedApiId of managedApiIds) {
            const response = await rest(`${managedApiId}?api-version=${core.managedApis}`, { context: 'web/managedApis.json' });
            if (ok(response)) { managedApis.push(response.json); } else { managedApisFailed++; }
        }
        write('web/managedApis.json', managedApis);
        sections['web/managedApis'] = { status: !managedApisFailed ? 'ok' : managedApis.length ? 'partial' : 'failed', count: managedApis.length, failed: managedApisFailed };

        //resources in other subscriptions that this one relies on, in id order: activity log destinations, data collection
        //rules and peered virtual networks. Requested by lowercase id; id and type as the response has them
        const referenced = new Set();
        if (['ok', 'partial'].includes(sections['subscription/diagnosticSettings']?.status)) {
            for (const setting of vfs.entry(`${root}/subscription/diagnosticSettings.json`)?.value ?? []) {
                for (const id of [prop(setting, 'properties.workspaceId'), prop(setting, 'properties.storageAccountId')]) { if (id) { referenced.add(String(id).toLowerCase()); } }
            }
        }
        for (const itemResult of itemResults) { for (const id of (itemResult.referencedIds ?? [])) { if (id) { referenced.add(id.toLowerCase()); } } }
        const ownPrefix = `/subscriptions/${subscriptionId.toLowerCase()}/`;
        const referencedIds = [...referenced].filter(id => !id.startsWith(ownPrefix) && /\/providers\/[^/]+\/[^/]+\/[^/]+$/.test(id)).sort();
        log(`Resources in other subscriptions (${referencedIds.length})`);
        const referencedRecords = [];
        for (const id of referencedIds) {
            const type = id.replace(/^.*\/providers\/([^/]+)\/([^/]+)\/[^/]+$/, '$1/$2');
            const itemFailures = [];
            const record = { id, type, apiVersion: null, resource: null, children: {}, failures: itemFailures };
            for (const apiVersion of (apiVersions[type] ?? [])) {
                if (!apiVersion) { continue; }
                const response = await rest(`${id}?api-version=${apiVersion}`, { context: 'subscription/referencedResources.json', expectedStatus: [400, 403, 404] });
                if (ok(response)) {
                    record.resource = response.json;
                    record.apiVersion = apiVersion;
                    if (prop(response.json, 'id')) { record.id = prop(response.json, 'id'); }
                    if (prop(response.json, 'type')) { record.type = prop(response.json, 'type'); }
                    break;
                }
                itemFailures.push({ path: id, apiVersion, statusCode: response.statusCode, errorCode: response.errorCode });
                if (response.statusCode !== 400) { break; }
            }
            if (record.resource !== null) {
                const cache = {};
                for (const path of (plan.referencedChildMap[type] ?? [])) { record.children[path] = await childResource(record.id, record.type, path, null, cache, itemFailures); }
            }
            referencedRecords.push(record);
        }
        write('subscription/referencedResources.json', referencedRecords);
        const referencedRead = referencedRecords.filter(r => r.resource !== null).length;
        sections['subscription/referencedResources'] = { status: referencedRead === referencedRecords.length ? 'ok' : referencedRead ? 'partial' : 'failed', count: referencedRead, failed: referencedRecords.length - referencedRead };

        if (!skipResourceGraph) {
            log('Resource Graph tables');
            let tablesDone = 0;
            for (const table of plan.resourceGraphTables) {
                sections[`resourceGraph/${table}`] = await exportResourceGraphTable(table, `resourceGraph/${table}.json`);
                progress({ phase: 'resourceGraph', done: ++tablesDone, total: plan.resourceGraphTables.length });
            }
        }

        if (activityLogDays > 0) {
            const activityLogUri = `/subscriptions/${subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values?api-version=${core.activityLog}&$filter=`;
            const encodeFilter = filter => encodeURIComponent(filter).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
            //restores and failovers over the whole window, by resource provider
            log(`Activity log (${activityLogDays} days)`);
            const recoveryOperations = [];
            const recoveryNames = new Set(plan.activityLogRecoveryOperations.map(name => name.toLowerCase()));
            const seenRecovery = new Set();
            let failedProviders = 0;
            for (const provider of plan.activityLogRecoveryProviders) {
                const filter = `eventTimestamp ge '${formatDate(startDate.addMs(-activityLogDays * 86400000), 'o')}' and eventTimestamp le '${formatDate(startDate, 'o')}' and resourceProvider eq '${provider}'`;
                const result = await paged(activityLogUri + encodeFilter(filter), {
                    context: 'activityLog/recoveryOperations', seenIds: seenRecovery, idProperty: 'eventDataId', onItem: e => {
                        if (recoveryNames.has(String(prop(e, 'operationName.value') ?? '').toLowerCase())) { recoveryOperations.push(e); }
                    }
                });
                if (!ok(result) || !result.complete) { failedProviders++; }
            }
            write('activityLog/recoveryOperations.json', recoveryOperations);
            sections['activityLog/recoveryOperations'] = { status: failedProviders === 0 ? 'ok' : failedProviders < plan.activityLogRecoveryProviders.length ? 'partial' : 'failed', count: recoveryOperations.length, days: activityLogDays };

            //the rest per day, newest first, until activityLogMaxEvents; windows do not overlap. The API returns some
            //events twice, identical, so they are deduplicated
            let duplicateCount = 0, failedDays = 0, daysCollected = 0;
            const seen = new Set();
            const events = [];
            //Write-ActivityLogEvent: the fields of activityLogFields, in that order
            const valueFields = new Set(plan.activityLogValueFields);
            const keepKey = {
                claims: key => plan.activityLogClaims.includes(key),
                httpRequest: key => plan.activityLogHttpRequest.includes(key),
                properties: key => !plan.activityLogDroppedProperties.includes(key)
            };
            const slim = event => {
                const out = {};
                for (const name of plan.activityLogFields) {
                    if (!Object.prototype.hasOwnProperty.call(event, name)) { continue; }
                    const value = event[name];
                    if (value === null || typeof value !== 'object' || Array.isArray(value)) { out[name] = value; continue; }
                    const keep = valueFields.has(name) ? key => key === 'value' : keepKey[name] ?? keepKey.properties;
                    out[name] = Object.fromEntries(Object.entries(value).filter(([key]) => keep(key)));
                }
                return out;
            };
            //Test-ActivityLogNoise: wildcard patterns as case-insensitive regular expressions
            const noiseRules = plan.activityLogNoise.map(([category, pattern, callers]) => ({
                category: category.toLowerCase(),
                pattern: new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i'),
                callers
            }));
            const isNoise = event => {
                const category = String(prop(event, 'category.value') ?? '').toLowerCase();
                const operation = String(prop(event, 'operationName.value') ?? '');
                const isUser = String(field(event, 'caller') ?? '').includes('@');
                return noiseRules.some(rule => (rule.category === '*' || category === rule.category) && rule.pattern.test(operation) && !(rule.callers === 'services' && isUser));
            };
            let noiseCount = 0;
            let windowEnd = startDate;
            while (daysCollected < activityLogDays && events.length < plan.activityLogMaxEvents) {
                const windowStart = windowEnd.addMs(-86400000);
                const filter = `eventTimestamp ge '${formatDate(windowStart, 'o')}' and eventTimestamp le '${formatDate(windowEnd, 'o')}'`;
                const result = await paged(activityLogUri + encodeFilter(filter), {
                    context: 'activityLog', seenIds: seen, idProperty: 'eventDataId', onItem: e => {
                        if (isNoise(e)) { noiseCount++; return; }
                        events.push(slim(e));
                    }
                });
                daysCollected++;
                if (!ok(result) || !result.complete) { failedDays++; }
                duplicateCount += result.duplicates;
                windowEnd = windowStart.addTicks(-1);
                progress({ phase: 'activityLog', done: daysCollected, total: activityLogDays });
            }
            const truncated = daysCollected < activityLogDays;
            if (truncated) { log(`  ${events.length} events in the last ${daysCollected} days, the most kept; older days are left out`); }
            write('activityLog/activityLog.json', events);
            sections['activityLog/activityLog'] = { status: failedDays === 0 ? 'ok' : failedDays < daysCollected ? 'partial' : 'failed', count: events.length, noiseSkipped: noiseCount, duplicatesSkipped: duplicateCount, days: activityLogDays, daysCollected, truncated, failedDays };
        }

        counts.referencedPrincipals = principalIds.size;
        if (!skipGraph) {
            log(`Entra ID (${principalIds.size} referenced principals)`);
            progress({ phase: 'graph', done: 0, total: 1 });
            try {
                const graphClaims = tokenClaims(await getToken('Graph'));
                caller.graphRoles = graphClaims.roles ?? (graphClaims.scp ? graphClaims.scp.split(' ') : []);
                const identitySections = await exportEntraData(principalIds);
                for (const [key, value] of Object.entries(identitySections)) { sections[`identity/${key}`] = value; }
            } catch (e) {
                if (e?.name === 'AbortError') { throw e; }
                log(`Entra ID collection failed: ${e?.message ?? e}`);
                sections.identity = { status: 'failed', message: e?.message ?? String(e) };
            }
            progress({ phase: 'graph', done: 1, total: 1 });
        }
        runStatus = 'completed';
    } catch (e) {
        if (e?.name === 'AbortError') { throw e; }
        fatalError = e?.message ?? String(e);
        log(`Run failed: ${fatalError}`);
    } finally {
        const completed = new PSDate(Date.now(), 'Utc');
        const byCategory = {};
        for (const category of [...new Set(failures.map(f => f.category))].sort()) { byCategory[category] = failures.filter(f => f.category === category).length; }
        write('failures.json', failures);
        write('manifest.json', {
            schemaVersion: plan.schemaVersion,
            scriptVersion: plan.scriptVersion,
            status: runStatus,
            error: fatalError,
            startedAt,
            completedAt: formatDate(completed, 'o'),
            durationSeconds: Math.floor((completed.ms - startDate.ms) / 1000),
            environment,
            subscription: { id: subscriptionId, displayName: prop(subscriptionInfo, 'displayName'), state: prop(subscriptionInfo, 'state'), tenantId },
            authentication: { method: authMethod, clientId, caller },
            parameters: { activityLogDays, skipGraph, skipResourceGraph, throttleLimit, compactJson: false },
            counts,
            sections,
            failures: { total: failures.length, byCategory },
            host: { powerShell: null, os: globalThis.navigator?.userAgent ?? (globalThis.process ? `node ${process.version}` : null), collector }
        });
    }
    if (runStatus !== 'completed') { throw new Error(`Ingestion failed: ${fatalError}`); }
    //data sections that could not be read (fully): the tests that need them report Unknown
    const issues = [];
    for (const [name, section] of Object.entries(sections)) {
        if (!['failed', 'partial'].includes(section.status)) { continue; }
        const failure = failures.find(f => f.context === `${name}.json`);
        issues.push({
            section: name,
            status: section.status,
            detail: failure ? describeFailure(failure) : (section.message ?? (section.statusCode !== undefined ? `HTTP ${section.statusCode}` : section.status))
        });
    }
    return { root, folder, resources: counts.resources, failedRequests: failures.length, issues };

    //#endregion
}

//an ingestion folder of the runtime file system as files for a zip, JSON indented like the PowerShell ingestion writes it
export function ingestFiles(vfs, root) {
    return vfs.snapshot(root).map(({ relative, entry }) => ({
        name: relative,
        text: entry.kind === 'json' ? toJson(entry.value, { depth: 1000 }) : (entry.text ?? '')
    }));
}
