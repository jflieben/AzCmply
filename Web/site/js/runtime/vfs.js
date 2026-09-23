//In-memory file system for the generated scripts. Paths are absolute, '/'-separated and case-insensitive (as on Windows).
//A file holds text, a parsed JSON value (from the ingest, serialized only when read as text) or a generated script.
import { parseJson, toJson } from './json.js';
import { PSError } from './types.js';

export class VFS {
    constructor() {
        this.files = new Map();   //lowercase path -> entry
        this.dirs = new Map();    //lowercase path -> display path
        this.cwd = '/work';
        this.mkdir('/');
        this.mkdir(this.cwd);
    }

    //absolute normalized path; relative paths resolve against the working directory
    resolve(path) {
        let p = String(path ?? '').replace(/\\/g, '/');
        if (/^[A-Za-z]:\//.test(p)) { p = '/' + p.slice(3); }
        if (!p.startsWith('/')) { p = this.cwd + '/' + p; }
        const parts = [];
        for (const seg of p.split('/')) {
            if (seg === '' || seg === '.') { continue; }
            if (seg === '..') { parts.pop(); continue; }
            parts.push(seg);
        }
        return '/' + parts.join('/');
    }

    join(...segments) { return this.resolve(segments.filter(s => s !== '').join('/')); }

    key(path) { return this.resolve(path).toLowerCase(); }

    mkdir(path) {
        const full = this.resolve(path);
        let current = '';
        this.dirs.set('/', '/');
        for (const seg of full.split('/').filter(Boolean)) {
            current += '/' + seg;
            const k = current.toLowerCase();
            if (!this.dirs.has(k)) { this.dirs.set(k, current); }
        }
        return full;
    }

    parentOf(path) {
        const full = this.resolve(path);
        const i = full.lastIndexOf('/');
        return i <= 0 ? '/' : full.slice(0, i);
    }

    put(path, entry) {
        const full = this.resolve(path);
        if (this.dirs.has(full.toLowerCase())) { throw new PSError(`Access to the path '${full}' is denied.`); }
        this.mkdir(this.parentOf(full));
        entry.path = full;
        entry.mtime = entry.mtime ?? Date.now();
        this.files.set(full.toLowerCase(), entry);
    }

    writeText(path, text, mtime) { this.put(path, { kind: 'text', text: String(text), mtime }); }
    writeJson(path, value, mtime) { this.put(path, { kind: 'json', value, mtime }); }
    writeBytes(path, bytes, mtime) { this.put(path, { kind: 'bytes', bytes, mtime }); }
    registerScript(path, module) { this.put(path, { kind: 'script', module, text: '' }); }

    entry(path) { return this.files.get(this.key(path)) ?? null; }
    isFile(path) { return this.files.has(this.key(path)); }
    isDir(path) { return this.dirs.has(this.key(path)); }
    exists(path) { return this.isFile(path) || this.isDir(path); }

    readText(path) {
        const e = this.entry(path);
        if (!e) { throw new PSError(`Could not find file '${this.resolve(path)}'.`); }
        switch (e.kind) {
            case 'text': return e.text;
            case 'json': return toJson(e.value, { depth: 1000 });
            case 'bytes': return new TextDecoder('utf-8').decode(e.bytes);
            default: return e.text ?? '';
        }
    }

    //parsed content of a JSON file; parsed once and kept, like the ingestion cache of the analyzer
    readJson(path, options) {
        const e = this.entry(path);
        if (!e) { return undefined; }
        if (e.kind === 'json') { return e.value; }
        const value = parseJson(this.readText(path), options);
        this.files.set(this.key(path), { kind: 'json', value, path: e.path, mtime: e.mtime });
        return value;
    }

    //files and directories below a directory, sorted by name
    list(path, { recurse = false } = {}) {
        const base = this.key(path);
        const prefix = base === '/' ? '/' : base + '/';
        const out = [];
        for (const [k, e] of this.files) {
            if (!k.startsWith(prefix)) { continue; }
            if (!recurse && k.slice(prefix.length).includes('/')) { continue; }
            out.push({ path: e.path, isDir: false, mtime: e.mtime, size: e.kind === 'text' ? e.text.length : 0 });
        }
        for (const [k, display] of this.dirs) {
            if (k === base || !k.startsWith(prefix)) { continue; }
            if (!recurse && k.slice(prefix.length).includes('/')) { continue; }
            out.push({ path: display, isDir: true, mtime: 0, size: 0 });
        }
        out.sort((a, b) => a.path.toLowerCase() < b.path.toLowerCase() ? -1 : a.path.toLowerCase() > b.path.toLowerCase() ? 1 : 0);
        return out;
    }

    remove(path, { recurse = true } = {}) {
        const k = this.key(path);
        this.files.delete(k);
        if (this.dirs.has(k)) {
            const prefix = k + '/';
            for (const f of Array.from(this.files.keys())) { if (f.startsWith(prefix)) { if (!recurse) { throw new PSError(`The item at ${path} has children.`); } this.files.delete(f); } }
            for (const d of Array.from(this.dirs.keys())) { if (d === k || d.startsWith(prefix)) { this.dirs.delete(d); } }
        }
    }

    //all files below a directory as { relativePath: entry }, for export
    snapshot(path) {
        const base = this.key(path);
        const prefix = base + '/';
        const out = [];
        for (const [k, e] of this.files) {
            if (k.startsWith(prefix)) { out.push({ relative: e.path.slice(prefix.length), entry: e }); }
        }
        return out.sort((a, b) => a.relative < b.relative ? -1 : 1);
    }
}
