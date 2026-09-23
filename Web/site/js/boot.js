//Starts the page with the files of the uploaded version. index.html loads this file as js/boot.js?v=<build>, a build id
//Convert-AzCmplyToWeb.ps1 derives from the site's contents. Hosts may let browsers keep scripts for days, so the first
//time this browser sees a build, every file of the page is fetched again past the browser cache before the page starts;
//without that a visitor could run a mix of old and new scripts.
const build = new URL(import.meta.url).searchParams.get('v') ?? '';
const KEY = 'azcmply.build';

async function refreshFiles() {
    let seen = null;
    try { seen = localStorage.getItem(KEY); } catch { /* storage blocked: refresh every time */ }
    if (!build || seen === build) { return; }
    try {
        const manifest = await (await fetch(`generated/manifest.json?v=${encodeURIComponent(build)}`, { cache: 'no-store' })).json();
        await Promise.all((manifest.files ?? []).map(file => fetch(file, { cache: 'reload' }).catch(() => null)));
        try { localStorage.setItem(KEY, build); } catch { /* next visit refreshes again */ }
    } catch {
        //offline or blocked: start with what the browser has
    }
}

await refreshFiles();
await import('./app.js');
