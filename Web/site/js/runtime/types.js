//PowerShell and .NET value types used by code generated with Convert-AzCmplyToWeb.ps1.
//Plain JS values stand in where the semantics match: string, number, boolean, null, Array (object[] and List[T]),
//plain objects (PSCustomObject, including parsed JSON).

//AutomationNull: the result of a pipeline that wrote nothing. Equal to $null, but enumerates as zero items.
export const ANULL = Object.freeze(Object.create(null));

export function isNull(v) { return v === null || v === undefined || v === ANULL; }

//key prefix that keeps integer-like JSON property names in document order (JS moves them to the front otherwise)
export const INT_KEY = '\u0000';

let objectIds = new WeakMap();
let nextObjectId = 1;
function objectKey(o) {
    let id = objectIds.get(o);
    if (!id) { id = nextObjectId++; objectIds.set(o, id); }
    return 'o' + id;
}

//hashtable key normalization: strings compare case-insensitively, other types by value, objects by identity
export function normKey(k) {
    if (k === null || k === undefined || k === ANULL) { return 'z'; }
    switch (typeof k) {
        case 'string': return 's' + k.toLowerCase();
        case 'number': return 'n' + k;
        case 'boolean': return 'b' + k;
        default:
            if (k instanceof PSDate) { return 'd' + k.ms + '.' + k.ticks; }
            return objectKey(k);
    }
}

export class PSHashtable {
    constructor(ordered = false) { this.ordered = ordered; this.map = new Map(); }
    get size() { return this.map.size; }
    has(k) { return this.map.has(normKey(k)); }
    get(k) { const e = this.map.get(normKey(k)); return e === undefined ? null : e[1]; }
    set(k, v) {
        const nk = normKey(k);
        const e = this.map.get(nk);
        if (e) { e[1] = v; } else { this.map.set(nk, [k, v]); }
    }
    add(k, v) {
        if (this.has(k)) { throw new Error(`Item has already been added. Key in dictionary: '${k}'  Key being added: '${k}'`); }
        this.set(k, v);
    }
    delete(k) { this.map.delete(normKey(k)); }
    keys() { return Array.from(this.map.values(), e => e[0]); }
    values() { return Array.from(this.map.values(), e => e[1]); }
    entries() { return Array.from(this.map.values(), e => new DictionaryEntry(e[0], e[1])); }
    clone() { const c = new PSHashtable(this.ordered); for (const [nk, e] of this.map) { c.map.set(nk, [e[0], e[1]]); } return c; }
}

export class DictionaryEntry {
    constructor(key, value) { this.Key = key; this.Value = value; }
}

export class PSHashSet {
    constructor(ignoreCase = false) { this.ignoreCase = ignoreCase; this.map = new Map(); }
    norm(v) {
        if (typeof v === 'string') { return 's' + (this.ignoreCase ? v.toLowerCase() : v); }
        return normKey(v);
    }
    get size() { return this.map.size; }
    add(v) { const k = this.norm(v); if (this.map.has(k)) { return false; } this.map.set(k, v); return true; }
    has(v) { return this.map.has(this.norm(v)); }
    delete(v) { return this.map.delete(this.norm(v)); }
    items() { return Array.from(this.map.values()); }
}

export class StringBuilder {
    constructor(text = '') { this.parts = text ? [text] : []; }
    append(s) { this.parts.push(s); return this; }
    toString() { const s = this.parts.join(''); this.parts = s ? [s] : []; return s; }
}

const TICKS_PER_MS = 10000;

//System.DateTime (kind 'Utc', 'Local' or 'Unspecified') and System.DateTimeOffset (kind 'Offset').
//ms is the UTC instant; Unspecified dates are stored as if they were local. ticks holds the 100ns remainder.
export class PSDate {
    constructor(ms, kind = 'Utc', ticks = 0, offsetMinutes = 0) {
        this.ms = ms; this.kind = kind; this.ticks = ticks; this.offset = offsetMinutes;
    }
    static fromParts(y, mo, d, h = 0, mi = 0, s = 0, msec = 0, kind = 'Unspecified') {
        const ms = kind === 'Utc' ? Date.UTC(y, mo - 1, d, h, mi, s, msec) : new Date(y, mo - 1, d, h, mi, s, msec).getTime();
        return new PSDate(ms, kind);
    }
    //wall clock components in the date's own kind
    parts() {
        if (this.kind === 'Utc') {
            const d = new Date(this.ms);
            return { y: d.getUTCFullYear(), mo: d.getUTCMonth() + 1, d: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds(), ms: d.getUTCMilliseconds(), dow: d.getUTCDay() };
        }
        if (this.kind === 'Offset') {
            const d = new Date(this.ms + this.offset * 60000);
            return { y: d.getUTCFullYear(), mo: d.getUTCMonth() + 1, d: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds(), ms: d.getUTCMilliseconds(), dow: d.getUTCDay() };
        }
        const d = new Date(this.ms);
        return { y: d.getFullYear(), mo: d.getMonth() + 1, d: d.getDate(), h: d.getHours(), mi: d.getMinutes(), s: d.getSeconds(), ms: d.getMilliseconds(), dow: d.getDay() };
    }
    offsetMinutes() {
        if (this.kind === 'Utc') { return 0; }
        if (this.kind === 'Offset') { return this.offset; }
        return -new Date(this.ms).getTimezoneOffset();
    }
    toUniversal() { return new PSDate(this.ms, 'Utc', this.ticks); }
    toLocal() { return new PSDate(this.ms, 'Local', this.ticks); }
    addMs(ms) {
        const whole = Math.floor(ms);
        let ticks = this.ticks + Math.round((ms - whole) * TICKS_PER_MS);
        let carry = Math.floor(ticks / TICKS_PER_MS);
        ticks -= carry * TICKS_PER_MS;
        return new PSDate(this.ms + whole + carry, this.kind, ticks, this.offset);
    }
    addTicks(t) {
        let total = this.ticks + t;
        const carry = Math.floor(total / TICKS_PER_MS);
        return new PSDate(this.ms + carry, this.kind, total - carry * TICKS_PER_MS, this.offset);
    }
    //.NET DateTime ticks since 0001-01-01
    get totalTicks() { return (this.ms + 62135596800000) * TICKS_PER_MS + this.ticks; }
    compare(other) { return this.ms !== other.ms ? (this.ms < other.ms ? -1 : 1) : (this.ticks - other.ticks); }
}

export class TimeSpan {
    constructor(ms) { this.ms = ms; }
    get totalDays() { return this.ms / 86400000; }
}

export class PSVersion {
    constructor(parts) { this.parts = parts; }
    compare(o) {
        for (let i = 0; i < 4; i++) {
            const a = i < this.parts.length ? this.parts[i] : -1;
            const b = i < o.parts.length ? o.parts[i] : -1;
            if (a !== b) { return a < b ? -1 : 1; }
        }
        return 0;
    }
    toString() { return this.parts.join('.'); }
}

export class IPAddress {
    constructor(bytes) { this.bytes = bytes; }
    get family() { return this.bytes.length === 4 ? 'InterNetwork' : 'InterNetworkV6'; }
}

//System.Type as returned by a type literal such as [string]
export class PSType {
    constructor(name) { this.name = name; }
}

//[ref]$variable: reads and writes the variable it was made from
export class PSRef {
    constructor(get, set) { this.get = get; this.set = set; }
    get Value() { return this.get(); }
    set Value(v) { this.set(v); }
}

//a regex Match, Group or Capture
export class RegexMatch {
    constructor(m, groupNames) { this.m = m; this.groupNames = groupNames; }
    get Value() { return this.m[0]; }
    get Index() { return this.m.index; }
    get Length() { return this.m[0].length; }
    get Success() { return true; }
}

//an object the runtime creates (FileInfo, GroupInfo, PSObject views, ...): a type name and a property bag
export class NativeObject {
    constructor(type, props, text) { this.type = type; this.props = props; this.text = text; }
}

export class ScriptBlock {
    //meta: { params, adv, text, file }; body: (S, O) => void
    constructor(meta, body) { this.meta = meta; this.body = body; }
}

export class PSFunction {
    constructor(name, block) { this.name = name; this.block = block; }
}

//the thrown value of a PowerShell error; catch blocks see it as $_ (an ErrorRecord)
export class PSError extends Error {
    constructor(message, target) {
        super(message);
        this.target = target;
        this.psPosition = null;
    }
}

export class ErrorRecord {
    constructor(error, position) {
        this.error = error;
        this.position = position;
    }
}

//marker for a named parameter token in a command's argument list: -Name, or -Name:value
export class NamedArg {
    constructor(name, value, hasValue) { this.name = name; this.value = value; this.hasValue = hasValue; }
}

export function isDict(v) { return v instanceof PSHashtable; }

//PSCustomObject: a plain object (parsed JSON or [pscustomobject] cast)
export function isPSObject(v) {
    if (v === null || typeof v !== 'object' || v === ANULL) { return false; }
    const proto = Object.getPrototypeOf(v);
    return proto === Object.prototype || proto === null;
}

//enumerated when written to the pipeline, iterated by foreach and joined in strings
export function isEnumerable(v) {
    return Array.isArray(v) || v instanceof PSHashSet || v instanceof Uint8Array || v instanceof MatchCollection || v instanceof GroupCollection;
}

export function toArray(v) {
    if (Array.isArray(v)) { return v; }
    if (v instanceof PSHashSet) { return v.items(); }
    if (v instanceof Uint8Array) { return Array.from(v); }
    if (v instanceof MatchCollection || v instanceof GroupCollection) { return v.items; }
    return [v];
}

export class MatchCollection {
    constructor(items) { this.items = items; }
}

export class GroupCollection {
    constructor(items, names) { this.items = items; this.names = names; }
}

//own property names of a PSCustomObject, with the integer-key marker removed
export function objectKeys(o) {
    const keys = Object.keys(o);
    for (let i = 0; i < keys.length; i++) { if (keys[i].charCodeAt(0) === 0) { keys[i] = keys[i].slice(1); } }
    return keys;
}

//the stored key for a property name of a PSCustomObject, matched case-insensitively; undefined when absent
export function findObjectKey(o, name) {
    if (Object.prototype.hasOwnProperty.call(o, name)) { return name; }
    const marked = INT_KEY + name;
    if (Object.prototype.hasOwnProperty.call(o, marked)) { return marked; }
    const lower = name.toLowerCase();
    for (const k of Object.keys(o)) {
        const plain = k.charCodeAt(0) === 0 ? k.slice(1) : k;
        if (plain.toLowerCase() === lower) { return k; }
    }
    return undefined;
}
