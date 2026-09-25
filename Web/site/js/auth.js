//Sign-in with Microsoft Entra ID for a single-page application: the OAuth 2.0 authorization code flow with PKCE.
//One sign-in gives an Azure Resource Manager token and a refresh token, which is redeemed for Microsoft Graph tokens.
//Tokens stay in this browser tab (memory, and the refresh token in sessionStorage so a reload keeps the session).
import plan from '../generated/ingest-plan.js';

const SESSION_KEY = 'azcmply.session';
const PENDING_KEY = 'azcmply.pending';

let session = null;
const accessTokens = new Map();

function endpoints(cloud) {
    const e = plan.cloudEndpoints[cloud];
    if (!e) { throw new Error(`Unknown cloud ${cloud}`); }
    return e;
}

function base64Url(bytes) {
    let s = '';
    for (const b of bytes) { s += String.fromCharCode(b); }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomString(length = 32) { return base64Url(crypto.getRandomValues(new Uint8Array(length))); }

export function redirectUri() { return location.origin + location.pathname; }

function decodeJwt(token) {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const bytes = Uint8Array.from(atob(part + '='.repeat((4 - part.length % 4) % 4)), c => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
}

function scopeFor(cloud, resource) { return `${endpoints(cloud)[resource]}/.default`; }

//a readable explanation for the Entra ID errors people run into when setting this up
export function explainError(code, description) {
    const text = description ?? '';
    if (/AADSTS65001|AADSTS90094|AADSTS90008/.test(text)) {
        return 'The app has not been given consent in this tenant. An administrator (Global Administrator, Privileged Role Administrator or Cloud Application Administrator) grants it once with the admin consent link below.';
    }
    if (/AADSTS50011/.test(text)) { return `The redirect URI of this page (${redirectUri()}) is not registered on the app registration as a single-page application redirect URI.`; }
    if (/AADSTS700016/.test(text)) { return 'The application (client) id was not found in this tenant or cloud. Check the client id, or use the multi-tenant JSolve app.'; }
    if (/AADSTS9002326|AADSTS9002327/.test(text)) { return `The redirect URI of this page (${redirectUri()}) is registered as a web redirect URI; it must be of the type single-page application.`; }
    if (/AADSTS50020|AADSTS50177/.test(text)) { return 'Your account is not a member or guest of this tenant. Sign in with an account of the tenant, or enter the tenant id you are a guest in.'; }
    if (/AADSTS53003|AADSTS530003/.test(text)) { return 'Conditional Access blocked this sign-in. Ask an administrator which conditions apply to this app.'; }
    if (/AADSTS700082|AADSTS700084|AADSTS50173/.test(text)) { return 'The session expired. Sign in again.'; }
    return text.split(/\r?\n/)[0] || code || 'Sign-in failed.';
}

async function tokenRequest(settings, body) {
    const response = await fetch(`${endpoints(settings.cloud).Login}/${encodeURIComponent(settings.tenant)}/oauth2/v2.0/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: settings.clientId, ...body })
    });
    const json = await response.json().catch(() => ({}));
    if (!response.ok) {
        const error = new Error(explainError(json.error, json.error_description));
        error.code = json.error;
        error.description = json.error_description;
        error.consent = /AADSTS65001|AADSTS90094|AADSTS90008/.test(json.error_description ?? '');
        throw error;
    }
    return json;
}

function save() {
    try { if (session) { sessionStorage.setItem(SESSION_KEY, JSON.stringify(session)); } else { sessionStorage.removeItem(SESSION_KEY); } } catch { /* storage blocked: the session lasts until reload */ }
}

function remember(resource, json) {
    accessTokens.set(resource, { token: json.access_token, expires: Date.now() + (json.expires_in ?? 3600) * 1000 });
    if (json.refresh_token) { session.refreshToken = json.refresh_token; }
    save();
}

//starts the sign-in: the browser leaves for the Microsoft sign-in page and comes back to this page
export async function signIn(settings, { prompt = 'select_account' } = {}) {
    const verifier = randomString(48);
    const challenge = base64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
    const state = randomString(16);
    sessionStorage.setItem(PENDING_KEY, JSON.stringify({ verifier, state, settings, redirectUri: redirectUri() }));
    const query = new URLSearchParams({
        client_id: settings.clientId,
        response_type: 'code',
        redirect_uri: redirectUri(),
        response_mode: 'query',
        scope: `openid profile offline_access ${scopeFor(settings.cloud, 'Arm')}`,
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        prompt
    });
    location.assign(`${endpoints(settings.cloud).Login}/${encodeURIComponent(settings.tenant)}/oauth2/v2.0/authorize?${query}`);
}

//the admin consent page for the app in a tenant; an administrator grants its read permissions for everyone once
export function adminConsentUrl(settings) {
    const tenant = settings.tenant && !['organizations', 'common'].includes(settings.tenant) ? settings.tenant : 'organizations';
    const query = new URLSearchParams({ client_id: settings.clientId, redirect_uri: redirectUri(), state: 'adminconsent' });
    return `${endpoints(settings.cloud).Login}/${encodeURIComponent(tenant)}/adminconsent?${query}`;
}

//handles the return from the sign-in or admin consent page; null when the page was opened normally
export async function completeRedirect() {
    const params = new URLSearchParams(location.search);
    if (!params.has('code') && !params.has('error') && !params.has('admin_consent')) { return null; }
    history.replaceState(null, '', redirectUri());
    if (params.get('state') === 'adminconsent' || params.has('admin_consent')) {
        if (params.has('error')) { return { adminConsent: false, error: explainError(params.get('error'), params.get('error_description')) }; }
        return { adminConsent: true, tenant: params.get('tenant') };
    }
    const pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) ?? 'null');
    sessionStorage.removeItem(PENDING_KEY);
    if (params.has('error')) { return { error: explainError(params.get('error'), params.get('error_description')), consent: /AADSTS65001|AADSTS90094/.test(params.get('error_description') ?? '') }; }
    if (!pending || pending.state !== params.get('state')) { return { error: 'The sign-in response does not match a sign-in started here. Sign in again.' }; }
    const json = await tokenRequest(pending.settings, {
        grant_type: 'authorization_code',
        code: params.get('code'),
        redirect_uri: pending.redirectUri,
        code_verifier: pending.verifier,
        scope: `openid profile offline_access ${scopeFor(pending.settings.cloud, 'Arm')}`
    });
    const claims = json.id_token ? decodeJwt(json.id_token) : {};
    session = {
        settings: pending.settings,
        account: { name: claims.name ?? null, username: claims.preferred_username ?? null, tenantId: claims.tid ?? null, objectId: claims.oid ?? null },
        refreshToken: null
    };
    remember('Arm', json);
    return { account: session.account };
}

export function restore() {
    try { session = JSON.parse(sessionStorage.getItem(SESSION_KEY) ?? 'null'); } catch { session = null; }
    return session?.account ?? null;
}

export function account() { return session?.account ?? null; }
export function settings() { return session?.settings ?? null; }

//an access token for 'Arm' or 'Graph', renewed with the refresh token when it expires within five minutes
export async function getToken(resource) {
    if (!session) { throw new Error('Not signed in.'); }
    const cached = accessTokens.get(resource);
    if (cached && cached.expires > Date.now() + 300000) { return cached.token; }
    if (!session.refreshToken) { throw new Error('The session expired. Sign in again.'); }
    const json = await tokenRequest(session.settings, {
        grant_type: 'refresh_token',
        refresh_token: session.refreshToken,
        scope: `offline_access ${scopeFor(session.settings.cloud, resource)}`
    });
    remember(resource, json);
    return json.access_token;
}

export function signOut() {
    session = null;
    accessTokens.clear();
    save();
}
