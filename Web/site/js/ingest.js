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
        failures.push({ time: isoNow(), category, statusCode, errorCode: errorCode ?? null, message: message ?? null, method, uri, context: context ?? null });
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
            const transient = statusCode === 0 || statusCode === 408 || statusCode >= 500;
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
                //the master database does not support data masking and answers with a 500
                if (typeKey === 'microsoft.sql/servers/databases' && /\/databases\/master$/i.test(item.id) && /^dataMaskingPolicies/i.test(path)) { continue; }
                record.children[path] = await childResource(item.id, item.type, path, pinned, cache, itemFailures);
            }
            for (const path of (plan.textContentMap[typeKey] ?? [])) {
                const response = await rest(`${item.id}/${path}?api-version=${record.apiVersion}`, { context: item.id, expectedStatus: [400, 404], maxTransientRetries: 1 });
                if (ok(response)) { record.textContent[path] = response.json !== null ? JSON.stringify(response.json) : response.text; }
                else { itemFailures.push({ path: `${item.id}/${path}`, apiVersion: record.apiVersion, statusCode: response.statusCode, errorCode: response.errorCode }); }
            }
        }
        write(item.file, record);
        const ids = new Set();
        findPrincipalIds([record.resource], ids);
        for (const child of Object.values(record.children)) { findPrincipalIds(Array.isArray(child) ? child : [child], ids); }
        return { id: item.id, type: item.type, file: item.file, apiVersion: record.apiVersion, status: record.resource !== null ? 'ok' : 'failed', failureCount: itemFailures.length, principalIds: [...ids] };
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
    async function graphBatch(requests, expectedStatus = []) {
        const results = new Map();
        const attempts = new Map();
        const pending = [...requests.keys()];
        while (pending.length) {
            const batchKeys = pending.splice(0, 20);
            const body = JSON.stringify({ requests: batchKeys.map((key, i) => ({ id: String(i), method: 'GET', url: requests.get(key) })) });
            const response = await rest('/v1.0/$batch', { resource: 'Graph', method: 'POST', body, context: 'graph batch' });
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
                    if (!expectedStatus.includes(status)) { addFailure(`${endpoints.Graph}/v1.0${requests.get(key)}`, 'GET', status, result.errorCode, prop(itemBody, 'error.message'), 'graph batch item'); }
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

        log(`Graph: ${groupIds.size} groups`);
        const memberSelect = `$select=${plan.graphSelect.member}`;
        const groupRequests = new Map();
        for (const id of groupIds) {
            groupRequests.set(`members|${id}`, `/groups/${id}/transitiveMembers?${memberSelect}&$top=999`);
            groupRequests.set(`owners|${id}`, `/groups/${id}/owners?${memberSelect}`);
        }
        const groupResults = groupRequests.size ? await graphBatch(groupRequests) : new Map();
        const groupRecords = [];
        const additionalIds = new Set();
        for (const id of [...groupIds]) {
            const members = groupResults.get(`members|${id}`);
            const owners = groupResults.get(`owners|${id}`);
            for (const related of [...(members?.items ?? []), ...(owners?.items ?? [])]) {
                const relatedId = prop(related, 'id');
                switch (field(related, '@odata.type')) {
                    case '#microsoft.graph.user': userIds.add(relatedId); break;
                    case '#microsoft.graph.servicePrincipal': if (!objectsById.has(relatedId)) { additionalIds.add(relatedId); } break;
                    default: break;
                }
            }
            groupRecords.push({ id, transitiveMembers: members?.items ?? null, transitiveMembersError: members && members.statusCode >= 300 ? members.statusCode : null, owners: owners?.items ?? null });
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
            sections[`${folderPart}/${name}`] = await exportEndpoint(`/subscriptions/${subscriptionId}/${path}${separator}api-version=${apiVersion}`, `${folderPart}/${name}.json`, { method: method ?? 'GET', principalTarget: principalIds });
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

        if (!skipResourceGraph) {
            log('Resource Graph tables');
            let tablesDone = 0;
            for (const table of plan.resourceGraphTables) {
                sections[`resourceGraph/${table}`] = await exportResourceGraphTable(table, `resourceGraph/${table}.json`);
                progress({ phase: 'resourceGraph', done: ++tablesDone, total: plan.resourceGraphTables.length });
            }
        }

        if (activityLogDays > 0) {
            //queried per day; windows do not overlap. The API returns some events twice, identical, so they are deduplicated
            log(`Activity log (${activityLogDays} days)`);
            let eventCount = 0, duplicateCount = 0, failedDays = 0;
            const seen = new Set();
            const events = [];
            let windowEnd = startDate;
            for (let day = 0; day < activityLogDays; day++) {
                const windowStart = windowEnd.addMs(-86400000);
                const filter = `eventTimestamp ge '${formatDate(windowStart, 'o')}' and eventTimestamp le '${formatDate(windowEnd, 'o')}'`;
                const result = await paged(`/subscriptions/${subscriptionId}/providers/Microsoft.Insights/eventtypes/management/values?api-version=${core.activityLog}&$filter=${encodeURIComponent(filter).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase())}`,
                    { context: 'activityLog', seenIds: seen, idProperty: 'eventDataId', onItem: e => events.push(e) });
                if (!ok(result) || !result.complete) { failedDays++; }
                eventCount += result.count;
                duplicateCount += result.duplicates;
                windowEnd = windowStart.addTicks(-1);
                progress({ phase: 'activityLog', done: day + 1, total: activityLogDays });
            }
            write('activityLog/activityLog.json', events);
            sections['activityLog/activityLog'] = { status: failedDays === 0 ? 'ok' : failedDays < activityLogDays ? 'partial' : 'failed', count: eventCount, duplicatesSkipped: duplicateCount, days: activityLogDays, failedDays };
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
    return { root, folder, resources: counts.resources, failedRequests: failures.length };

    //#endregion
}

//an ingestion folder of the runtime file system as files for a zip, JSON indented like the PowerShell ingestion writes it
export function ingestFiles(vfs, root) {
    return vfs.snapshot(root).map(({ relative, entry }) => ({
        name: relative,
        text: entry.kind === 'json' ? toJson(entry.value, { depth: 1000 }) : (entry.text ?? '')
    }));
}
