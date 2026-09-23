//ConvertFrom-Json, ConvertTo-Json and ConvertTo-Csv with PowerShell 7.5 behavior.
import { ANULL, isNull, PSHashtable, PSDate, INT_KEY, isPSObject, isEnumerable, toArray, objectKeys, ScriptBlock } from './types.js';
import { toStr, parseDate, formatNumber, typeName } from './convert.js';

const INT_KEY_PATTERN = /([{,]\s*)"(\d+)"(\s*:)/g;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,7})?)?(?:Z|[+-]\d{2}:\d{2})?$/;

//JSON text to PowerShell values. Integer-like property names get a marker so they keep their document order.
//dateKind 'String' keeps ISO dates as text; 'Default' turns them into DateTime like ConvertFrom-Json does.
export function parseJson(text, { asHashtable = false, dateKind = 'Default' } = {}) {
    let source = String(text);
    const marked = /[{,]\s*"\d+"\s*:/.test(source);
    if (marked) { source = source.replace(INT_KEY_PATTERN, '$1"\\u0000$2"$3'); }
    let value = JSON.parse(source);
    if (asHashtable) { return toHashtables(value, dateKind !== 'String'); }
    if (dateKind !== 'String') { value = convertDates(value); }
    return value;
}

function convertDates(v) {
    if (typeof v === 'string') { return ISO_DATE.test(v) ? jsonDate(v) : v; }
    if (Array.isArray(v)) { for (let i = 0; i < v.length; i++) { v[i] = convertDates(v[i]); } return v; }
    if (v && typeof v === 'object') { for (const k of Object.keys(v)) { v[k] = convertDates(v[k]); } }
    return v;
}

//Newtonsoft RoundtripKind: 'Z' is UTC, an offset becomes local time, no zone stays unspecified
function jsonDate(s) {
    const d = parseDate(s);
    if (!d) { return s; }
    if (/Z$/i.test(s)) { return new PSDate(d.ms, 'Utc', d.ticks); }
    return d;
}

function toHashtables(v, dates) {
    if (Array.isArray(v)) { return v.map(x => toHashtables(x, dates)); }
    if (v && typeof v === 'object') {
        const h = new PSHashtable(true);
        for (const k of Object.keys(v)) { h.set(k.charCodeAt(0) === 0 ? k.slice(1) : k, toHashtables(v[k], dates)); }
        return h;
    }
    if (dates && typeof v === 'string' && ISO_DATE.test(v)) { return jsonDate(v); }
    return v;
}

//line and paragraph separators and C1 controls are escaped, as Newtonsoft does
const ESCAPED_CHARS = new RegExp('[' + String.fromCharCode(0x2028, 0x2029) + '\x7f-\x9f]', 'g');

function quote(s) {
    return JSON.stringify(s).replace(ESCAPED_CHARS, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function jsonNumber(n) {
    if (!Number.isFinite(n)) { return quote(String(n)); }
    if (Number.isInteger(n) && Math.abs(n) < 1e21) { return String(n); }
    return String(n).replace('e', 'E');
}

function jsonDateText(d) {
    const p = d.parts();
    const pad = (n, w) => String(n).padStart(w, '0');
    const frac = pad(p.ms * 10000 + d.ticks, 7).replace(/0+$/, '');
    let text = `${pad(p.y, 4)}-${pad(p.mo, 2)}-${pad(p.d, 2)}T${pad(p.h, 2)}:${pad(p.mi, 2)}:${pad(p.s, 2)}${frac ? '.' + frac : ''}`;
    if (d.kind === 'Utc') { return text + 'Z'; }
    if (d.kind === 'Unspecified') { return text; }
    const off = d.offsetMinutes();
    const abs = Math.abs(off);
    return `${text}${off < 0 ? '-' : '+'}${pad(Math.floor(abs / 60), 2)}:${pad(abs % 60, 2)}`;
}

//ConvertTo-Json. Objects deeper than depth are written as their string form, as PowerShell does (with a warning).
export function toJson(value, { depth = 2, compress = false, onTruncate } = {}) {
    let truncated = false;
    function write(v, level, indent) {
        if (v === null || v === undefined || v === ANULL) { return 'null'; }
        switch (typeof v) {
            case 'string': return quote(v);
            case 'number': return jsonNumber(v);
            case 'boolean': return v ? 'true' : 'false';
            default: break;
        }
        if (v instanceof PSDate) { return quote(jsonDateText(v)); }
        const isList = isEnumerable(v);
        const isMap = v instanceof PSHashtable || isPSObject(v);
        if (!isList && !isMap) { return quote(toStr(v)); }
        if (level > depth) { truncated = true; return quote(isList ? toArray(v).map(toStr).join(' ') : (isPSObject(v) ? toStr(v) : typeName(v))); }
        const inner = compress ? '' : indent + '  ';
        const nl = compress ? '' : '\n';
        if (isList) {
            const items = toArray(v);
            if (!items.length) { return '[]'; }
            return '[' + nl + items.map(x => inner + write(x, level + 1, inner)).join(',' + nl) + nl + indent + ']';
        }
        let entries;
        if (v instanceof PSHashtable) { entries = Array.from(v.map.values(), e => [toStr(e[0]), e[1]]); }
        else { const values = Object.values(v); entries = objectKeys(v).map((k, i) => [k, values[i]]); }
        if (!entries.length) { return '{}'; }
        const sep = compress ? ':' : ': ';
        return '{' + nl + entries.map(([k, x]) => inner + quote(k) + sep + write(x, level + 1, inner)).join(',' + nl) + nl + indent + '}';
    }
    const text = write(value, 0, '');
    if (truncated && onTruncate) { onTruncate(depth); }
    return text;
}

function csvValue(v, quoting) {
    let s;
    if (isNull(v)) { s = ''; }
    else if (isEnumerable(v)) { s = typeName(v); }
    else { s = toStr(v); }
    if (quoting === 'never') { return s; }
    if (quoting === 'asneeded' && !/[",\r\n]/.test(s)) { return s; }
    return '"' + s.replace(/"/g, '""') + '"';
}

//ConvertTo-Csv -NoTypeInformation; one string per line
export function toCsv(items, { quoting = 'always', delimiter = ',' } = {}) {
    const rows = items.filter(x => !isNull(x));
    if (!rows.length) { return []; }
    const first = rows[0];
    const columns = first instanceof PSHashtable ? first.keys().map(toStr) : isPSObject(first) ? objectKeys(first) : ['Length'];
    const cell = (name, row) => {
        if (row instanceof PSHashtable) { return row.get(name); }
        if (isPSObject(row)) { const i = objectKeys(row).findIndex(k => k.toLowerCase() === name.toLowerCase()); return i < 0 ? null : Object.values(row)[i]; }
        return name === 'Length' && typeof row === 'string' ? row.length : null;
    };
    const lines = [columns.map(c => csvValue(c, quoting)).join(delimiter)];
    for (const row of rows) { lines.push(columns.map(c => csvValue(cell(c, row), quoting)).join(delimiter)); }
    return lines;
}

export { formatNumber, ScriptBlock };
