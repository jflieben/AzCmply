//PowerShell value conversion, formatting and type tests.
import {
    ANULL, isNull, PSHashtable, PSHashSet, PSDate, TimeSpan, PSVersion, IPAddress, PSType, PSRef, RegexMatch,
    ScriptBlock, StringBuilder, DictionaryEntry, ErrorRecord, PSError, isPSObject, isEnumerable, toArray, objectKeys,
    MatchCollection, GroupCollection, isDict, NativeObject
} from './types.js';

export function psError(message) { return new PSError(message); }

//#region numbers

//digits and exponent of x rounded to `precision` significant digits (x finite, non-zero)
function sigDigits(x, precision) {
    const s = Math.abs(x).toExponential(precision - 1);
    const [mant, exp] = s.split('e');
    return { digits: mant.replace('.', ''), exp: parseInt(exp, 10) };
}

//.NET "G" formatting with the given precision, invariant culture
export function formatGeneral(x, precision = 15) {
    if (Number.isNaN(x)) { return 'NaN'; }
    if (x === Infinity) { return 'Infinity'; }
    if (x === -Infinity) { return '-Infinity'; }
    if (x === 0) { return Object.is(x, -0) ? '-0' : '0'; }
    let { digits, exp } = sigDigits(x, precision);
    digits = digits.replace(/0+$/, '') || '0';
    const sign = x < 0 ? '-' : '';
    if (exp >= precision || exp < -4) {
        const rest = digits.slice(1);
        const e = Math.abs(exp).toString().padStart(2, '0');
        return `${sign}${digits[0]}${rest ? '.' + rest : ''}E${exp < 0 ? '-' : '+'}${e}`;
    }
    if (exp < 0) { return `${sign}0.${'0'.repeat(-exp - 1)}${digits}`; }
    if (digits.length <= exp + 1) { return sign + digits + '0'.repeat(exp + 1 - digits.length); }
    return `${sign}${digits.slice(0, exp + 1)}.${digits.slice(exp + 1)}`;
}

//how PowerShell writes a number in a string
export function formatNumber(x) {
    if (Number.isInteger(x) && Math.abs(x) < 1e15) { return Object.is(x, -0) ? '-0' : String(x); }
    return formatGeneral(x, 15);
}

//a non-negative decimal digit string rounded half away from zero to `decimals` fraction digits
function roundDecimalString(intPart, fracPart, decimals) {
    if (fracPart.length <= decimals) { return [intPart, fracPart.padEnd(decimals, '0')]; }
    const keep = fracPart.slice(0, decimals);
    const roundUp = fracPart.charCodeAt(decimals) >= 53;
    if (!roundUp) { return [intPart, keep]; }
    const all = (intPart + keep).split('').map(Number);
    let i = all.length - 1;
    while (i >= 0) { if (all[i] === 9) { all[i] = 0; i--; } else { all[i]++; break; } }
    let joined = all.join('');
    if (i < 0) { joined = '1' + joined; }
    const newInt = joined.slice(0, joined.length - decimals) || '0';
    return [newInt, joined.slice(joined.length - decimals)];
}

//plain decimal representation of |x| from 15 significant digits, as .NET does before applying a format
function decimalParts(x, precision = 15) {
    if (x === 0) { return ['0', '']; }
    const { digits, exp } = sigDigits(x, precision);
    if (exp >= 0) {
        if (digits.length <= exp + 1) { return [digits + '0'.repeat(exp + 1 - digits.length), '']; }
        return [digits.slice(0, exp + 1), digits.slice(exp + 1).replace(/0+$/, '')];
    }
    return ['0', ('0'.repeat(-exp - 1) + digits).replace(/0+$/, '')];
}

function groupThousands(intPart) { return intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ','); }

//.NET numeric format string, invariant culture
export function formatNumberWith(x, format) {
    if (!format) { return formatNumber(x); }
    const standard = /^([A-Za-z])(\d{0,2})$/.exec(format);
    if (standard) {
        const kind = standard[1].toUpperCase();
        const precision = standard[2] === '' ? null : parseInt(standard[2], 10);
        const neg = x < 0 || Object.is(x, -0);
        const abs = Math.abs(x);
        switch (kind) {
            case 'D': {
                if (!Number.isInteger(x)) { throw psError('Format specifier was invalid.'); }
                return (neg ? '-' : '') + String(abs).padStart(precision ?? 0, '0');
            }
            case 'N': case 'F': {
                const [ip, fp] = roundDecimalString(...decimalParts(abs), precision ?? 2);
                const body = (kind === 'N' ? groupThousands(ip) : ip) + (fp ? '.' + fp : '');
                return (neg ? '-' : '') + body;
            }
            case 'P': {
                const [ip, fp] = roundDecimalString(...decimalParts(abs * 100), precision ?? 2);
                const body = groupThousands(ip) + (fp ? '.' + fp : '');
                return (neg ? '-' : '') + body + ' %';
            }
            case 'G': return formatGeneral(x, precision || 15);
            case 'R': return formatNumber(x);
            case 'X': {
                const hex = (x >>> 0).toString(16).padStart(precision ?? 0, '0');
                return standard[1] === 'X' ? hex.toUpperCase() : hex;
            }
            case 'E': {
                const s = abs.toExponential(precision ?? 6);
                const [m, e] = s.split('e');
                const ev = parseInt(e, 10);
                const body = `${m}${standard[1]}${ev < 0 ? '-' : '+'}${String(Math.abs(ev)).padStart(3, '0')}`;
                return (neg ? '-' : '') + body;
            }
            default: break;
        }
    }
    return formatCustomNumber(x, format);
}

//custom numeric format such as '0.#', '0.00', '#,##0', '00'
function formatCustomNumber(x, format) {
    const sections = splitSections(format);
    let section = sections[0];
    let negativeSection = false;
    if (x < 0 && sections.length > 1 && sections[1] !== '') { section = sections[1]; negativeSection = true; }
    if (x === 0 && sections.length > 2 && sections[2] !== '') { section = sections[2]; }
    let literalPrefix = '', literalSuffix = '', pattern = '';
    //separate literals from the digit placeholders
    const tokens = [];
    for (let i = 0; i < section.length; i++) {
        const c = section[i];
        if (c === "'" || c === '"') {
            const end = section.indexOf(c, i + 1);
            tokens.push({ lit: section.slice(i + 1, end < 0 ? undefined : end) });
            i = end < 0 ? section.length : end;
        } else if (c === '\\') {
            tokens.push({ lit: section[i + 1] ?? '' }); i++;
        } else if ('0#.,'.includes(c)) {
            tokens.push({ ph: c });
        } else if (c === '%') {
            tokens.push({ pct: true });
        } else {
            tokens.push({ lit: c });
        }
    }
    const firstPh = tokens.findIndex(t => t.ph);
    let lastPh = -1;
    for (let i = tokens.length - 1; i >= 0; i--) { if (tokens[i].ph) { lastPh = i; break; } }
    let percent = false;
    tokens.forEach((t, i) => {
        if (t.pct) { percent = true; }
        if (firstPh < 0 || i < firstPh) { literalPrefix += t.lit ?? (t.pct ? '%' : ''); }
        else if (i > lastPh) { literalSuffix += t.lit ?? (t.pct ? '%' : ''); }
        else if (t.ph) { pattern += t.ph; }
    });
    const dot = pattern.indexOf('.');
    const intPattern = dot < 0 ? pattern : pattern.slice(0, dot);
    const fracPattern = dot < 0 ? '' : pattern.slice(dot + 1).replace(/,/g, '');
    const grouping = /[0#],+[0#]/.test(intPattern);
    let value = Math.abs(x) * (percent ? 100 : 1);
    //trailing commas scale by 1000 each
    const scaleCommas = (intPattern.match(/,+$/) || [''])[0].length;
    if (scaleCommas) { value /= Math.pow(1000, scaleCommas); }
    const maxFrac = fracPattern.length;
    const minFrac = (fracPattern.match(/^0*/) || [''])[0].length;
    let [ip, fp] = roundDecimalString(...decimalParts(value), maxFrac);
    fp = fp.replace(/0+$/, '');
    if (fp.length < minFrac) { fp = fp.padEnd(minFrac, '0'); }
    const minInt = (intPattern.replace(/,/g, '').match(/0/g) || []).length;
    if (ip === '0' && minInt === 0) { ip = ''; }
    if (ip.length < minInt) { ip = ip.padStart(minInt, '0'); }
    if (grouping && ip) { ip = groupThousands(ip); }
    let body = ip + (fp ? '.' + fp : '');
    if (!body) { body = '0'; }
    const sign = (x < 0 || Object.is(x, -0)) && !negativeSection ? '-' : '';
    return sign + literalPrefix + body + literalSuffix;
}

function splitSections(format) {
    const sections = [];
    let current = '', quote = null;
    for (let i = 0; i < format.length; i++) {
        const c = format[i];
        if (quote) { current += c; if (c === quote) { quote = null; } continue; }
        if (c === "'" || c === '"') { quote = c; current += c; continue; }
        if (c === '\\') { current += c + (format[i + 1] ?? ''); i++; continue; }
        if (c === ';') { sections.push(current); current = ''; continue; }
        current += c;
    }
    sections.push(current);
    return sections;
}

//round half to even, as [math]::Round and [int] casts do
export function roundEven(x) {
    const r = Math.round(x);
    if (Math.abs(x % 1) === 0.5) { return 2 * Math.round(x / 2); }
    return r;
}

//[math]::Round(value, digits): scale, round half to even, scale back (the .NET algorithm)
export function mathRound(value, digits = 0, mode) {
    const away = typeof mode === 'string' && mode.toLowerCase() === 'awayfromzero';
    const round = away ? (v => Math.sign(v) * Math.round(Math.abs(v))) : roundEven;
    if (!digits) { return round(value); }
    const power = Math.pow(10, digits);
    return round(value * power) / power;
}

//string to number the way PowerShell converts it; NaN when it is not a number
export function parseNumber(s) {
    const t = s.trim();
    if (t === '') { return 0; }
    if (/^[+-]?0x[0-9a-f]+$/i.test(t)) { return parseInt(t, 16); }
    if (/^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/i.test(t)) { return Number(t); }
    return NaN;
}

export function toNumber(v) {
    if (isNull(v)) { return 0; }
    switch (typeof v) {
        case 'number': return v;
        case 'boolean': return v ? 1 : 0;
        case 'string': {
            const n = parseNumber(v);
            if (Number.isNaN(n)) { throw psError(`Cannot convert value "${v}" to type "System.Double". Error: "The input string '${v}' was not in a correct format."`); }
            return n;
        }
        default:
            if (Array.isArray(v) && v.length === 1) { return toNumber(v[0]); }
            if (v instanceof TimeSpan) { return v.ms * 10000; }
            throw psError(`Cannot convert the "${toStr(v)}" value of type "${typeName(v)}" to type "System.Double".`);
    }
}

export function toInt(v, typeLabel = 'System.Int32') {
    if (isNull(v)) { return 0; }
    if (typeof v === 'string') {
        const n = parseNumber(v);
        if (Number.isNaN(n)) { throw psError(`Cannot convert value "${v}" to type "${typeLabel}". Error: "The input string '${v}' was not in a correct format."`); }
        return roundEven(n);
    }
    return roundEven(toNumber(v));
}

//#endregion

//#region strings

const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

function pad(n, width) { return String(n).padStart(width, '0'); }

function offsetText(minutes, style) {
    const sign = minutes < 0 ? '-' : '+';
    const abs = Math.abs(minutes);
    const h = Math.floor(abs / 60), m = abs % 60;
    if (style === 'z') { return sign + h; }
    if (style === 'zz') { return sign + pad(h, 2); }
    return `${sign}${pad(h, 2)}:${pad(m, 2)}`;
}

//fraction digits of a date: milliseconds plus the 100ns remainder, 7 digits
function fraction7(date, p) { return pad(p.ms * 10000 + date.ticks, 7); }

//.NET DateTime.ToString with a standard or custom format, invariant culture
export function formatDate(date, format) {
    const p = date.parts();
    if (!format) { format = 'G'; }
    if (format.length === 1) {
        switch (format) {
            case 'o': case 'O': {
                const base = `${pad(p.y, 4)}-${pad(p.mo, 2)}-${pad(p.d, 2)}T${pad(p.h, 2)}:${pad(p.mi, 2)}:${pad(p.s, 2)}.${fraction7(date, p)}`;
                if (date.kind === 'Utc') { return base + 'Z'; }
                if (date.kind === 'Unspecified') { return base; }
                return base + offsetText(date.offsetMinutes(), 'zzz');
            }
            case 's': return `${pad(p.y, 4)}-${pad(p.mo, 2)}-${pad(p.d, 2)}T${pad(p.h, 2)}:${pad(p.mi, 2)}:${pad(p.s, 2)}`;
            case 'u': {
                const u = date.toUniversal().parts();
                return `${pad(u.y, 4)}-${pad(u.mo, 2)}-${pad(u.d, 2)} ${pad(u.h, 2)}:${pad(u.mi, 2)}:${pad(u.s, 2)}Z`;
            }
            case 'd': return `${pad(p.mo, 2)}/${pad(p.d, 2)}/${pad(p.y, 4)}`;
            case 'D': return `${DAYS[p.dow]}, ${pad(p.d, 2)} ${MONTHS[p.mo - 1]} ${pad(p.y, 4)}`;
            case 'g': return `${pad(p.mo, 2)}/${pad(p.d, 2)}/${pad(p.y, 4)} ${pad(p.h, 2)}:${pad(p.mi, 2)}`;
            case 'G': return `${pad(p.mo, 2)}/${pad(p.d, 2)}/${pad(p.y, 4)} ${pad(p.h, 2)}:${pad(p.mi, 2)}:${pad(p.s, 2)}`;
            case 't': return `${pad(p.h, 2)}:${pad(p.mi, 2)}`;
            case 'T': return `${pad(p.h, 2)}:${pad(p.mi, 2)}:${pad(p.s, 2)}`;
            case 'M': case 'm': return `${MONTHS[p.mo - 1]} ${pad(p.d, 2)}`;
            case 'Y': case 'y': return `${pad(p.y, 4)} ${MONTHS[p.mo - 1]}`;
            case 'r': case 'R': {
                const u = date.toUniversal().parts();
                return `${DAYS[u.dow].slice(0, 3)}, ${pad(u.d, 2)} ${MONTHS[u.mo - 1].slice(0, 3)} ${pad(u.y, 4)} ${pad(u.h, 2)}:${pad(u.mi, 2)}:${pad(u.s, 2)} GMT`;
            }
            case 'f': return `${DAYS[p.dow]}, ${pad(p.d, 2)} ${MONTHS[p.mo - 1]} ${pad(p.y, 4)} ${pad(p.h, 2)}:${pad(p.mi, 2)}`;
            case 'F': return `${DAYS[p.dow]}, ${pad(p.d, 2)} ${MONTHS[p.mo - 1]} ${pad(p.y, 4)} ${pad(p.h, 2)}:${pad(p.mi, 2)}:${pad(p.s, 2)}`;
            default: throw psError('Input string was not in a correct format.');
        }
    }
    let out = '';
    for (let i = 0; i < format.length;) {
        const c = format[i];
        if (c === "'" || c === '"') {
            const end = format.indexOf(c, i + 1);
            out += format.slice(i + 1, end < 0 ? format.length : end);
            i = end < 0 ? format.length : end + 1;
            continue;
        }
        if (c === '\\') { out += format[i + 1] ?? ''; i += 2; continue; }
        if (c === '%') { i++; continue; }
        let n = 1;
        while (format[i + n] === c) { n++; }
        switch (c) {
            case 'y': out += n === 2 ? pad(p.y % 100, 2) : n === 1 ? String(p.y % 100) : pad(p.y, n); break;
            case 'M': out += n >= 4 ? MONTHS[p.mo - 1] : n === 3 ? MONTHS[p.mo - 1].slice(0, 3) : n === 2 ? pad(p.mo, 2) : String(p.mo); break;
            case 'd': out += n >= 4 ? DAYS[p.dow] : n === 3 ? DAYS[p.dow].slice(0, 3) : n === 2 ? pad(p.d, 2) : String(p.d); break;
            case 'H': out += n >= 2 ? pad(p.h, 2) : String(p.h); break;
            case 'h': { const h12 = p.h % 12 || 12; out += n >= 2 ? pad(h12, 2) : String(h12); break; }
            case 'm': out += n >= 2 ? pad(p.mi, 2) : String(p.mi); break;
            case 's': out += n >= 2 ? pad(p.s, 2) : String(p.s); break;
            case 'f': out += fraction7(date, p).slice(0, Math.min(n, 7)); break;
            case 'F': {
                const digits = fraction7(date, p).slice(0, Math.min(n, 7)).replace(/0+$/, '');
                if (!digits && out.endsWith('.')) { out = out.slice(0, -1); }
                out += digits;
                break;
            }
            case 't': out += n >= 2 ? (p.h < 12 ? 'AM' : 'PM') : (p.h < 12 ? 'A' : 'P'); break;
            case 'K': out += date.kind === 'Utc' ? 'Z' : date.kind === 'Unspecified' ? '' : offsetText(date.offsetMinutes(), 'zzz'); break;
            case 'z': out += offsetText(date.offsetMinutes(), n === 1 ? 'z' : n === 2 ? 'zz' : 'zzz'); break;
            case 'g': out += 'A.D.'; break;
            default: out += c.repeat(n); break;
        }
        i += n;
    }
    return out;
}

//DateTime/DateTimeOffset parsing, invariant culture: ISO 8601 and the invariant 'MM/dd/yyyy HH:mm:ss' form.
//Without an offset the value is local time, or UTC with assumeUniversal. Returns null when unparseable.
export function parseDate(text, { assumeUniversal = false, offsetResult = false } = {}) {
    const s = String(text).trim();
    let m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,7}))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$/i.exec(s);
    let y, mo, d, h = 0, mi = 0, sec = 0, frac = '', zone;
    if (m) {
        y = Number(m[1]); mo = Number(m[2]); d = Number(m[3]);
        h = Number(m[4] ?? 0); mi = Number(m[5] ?? 0); sec = Number(m[6] ?? 0); frac = m[7] ?? ''; zone = m[8];
    } else {
        m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?$/.exec(s);
        if (!m) { return null; }
        mo = Number(m[1]); d = Number(m[2]); y = Number(m[3]);
        h = Number(m[4] ?? 0); mi = Number(m[5] ?? 0); sec = Number(m[6] ?? 0);
    }
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 59) { return null; }
    const fracTicks = frac ? Number(frac.padEnd(7, '0')) : 0;
    const msPart = Math.floor(fracTicks / 10000);
    const tickRest = fracTicks % 10000;
    let ms, offsetMinutes;
    if (zone) {
        offsetMinutes = 0;
        if (zone.toUpperCase() !== 'Z') {
            const zm = /^([+-])(\d{2}):?(\d{2})$/.exec(zone);
            offsetMinutes = (zm[1] === '-' ? -1 : 1) * (Number(zm[2]) * 60 + Number(zm[3]));
        }
        ms = Date.UTC(y, mo - 1, d, h, mi, sec, msPart) - offsetMinutes * 60000;
    } else if (assumeUniversal) {
        offsetMinutes = 0;
        ms = Date.UTC(y, mo - 1, d, h, mi, sec, msPart);
    } else {
        ms = new Date(y, mo - 1, d, h, mi, sec, msPart).getTime();
        offsetMinutes = -new Date(ms).getTimezoneOffset();
    }
    if (offsetResult) { return new PSDate(ms, 'Offset', tickRest, offsetMinutes); }
    //DateTime.Parse: a value with an offset becomes local time, without one it stays unspecified
    return new PSDate(ms, zone ? 'Local' : 'Unspecified', tickRest);
}

export function formatTimeSpan(ts) {
    let totalMs = ts.ms;
    const neg = totalMs < 0;
    totalMs = Math.abs(totalMs);
    const days = Math.floor(totalMs / 86400000);
    let rest = totalMs - days * 86400000;
    const h = Math.floor(rest / 3600000); rest -= h * 3600000;
    const mi = Math.floor(rest / 60000); rest -= mi * 60000;
    const s = Math.floor(rest / 1000); rest -= s * 1000;
    const frac = Math.round(rest * 10000);
    return `${neg ? '-' : ''}${days ? days + '.' : ''}${pad(h, 2)}:${pad(mi, 2)}:${pad(s, 2)}${frac ? '.' + pad(frac, 7) : ''}`;
}

export function typeName(v) {
    if (isNull(v)) { return 'null'; }
    switch (typeof v) {
        case 'string': return 'System.String';
        case 'boolean': return 'System.Boolean';
        case 'number': return Number.isInteger(v) ? 'System.Int32' : 'System.Double';
        default: break;
    }
    if (Array.isArray(v)) { return 'System.Object[]'; }
    if (v instanceof PSHashtable) { return v.ordered ? 'System.Collections.Specialized.OrderedDictionary' : 'System.Collections.Hashtable'; }
    if (v instanceof PSHashSet) { return 'System.Collections.Generic.HashSet`1[[System.String]]'; }
    if (v instanceof PSDate) { return v.kind === 'Offset' ? 'System.DateTimeOffset' : 'System.DateTime'; }
    if (v instanceof TimeSpan) { return 'System.TimeSpan'; }
    if (v instanceof PSVersion) { return 'System.Version'; }
    if (v instanceof ScriptBlock) { return 'System.Management.Automation.ScriptBlock'; }
    if (v instanceof DictionaryEntry) { return 'System.Collections.DictionaryEntry'; }
    if (v instanceof StringBuilder) { return 'System.Text.StringBuilder'; }
    if (v instanceof IPAddress) { return 'System.Net.IPAddress'; }
    if (v instanceof RegexMatch) { return 'System.Text.RegularExpressions.Match'; }
    if (v instanceof PSType) { return 'System.RuntimeType'; }
    if (v instanceof ErrorRecord) { return 'System.Management.Automation.ErrorRecord'; }
    if (v instanceof Uint8Array) { return 'System.Byte[]'; }
    if (isPSObject(v)) { return 'System.Management.Automation.PSCustomObject'; }
    if (v instanceof NativeObject) { return v.type; }
    return 'System.Object';
}

//how a value appears inside the @{...} text of a PSCustomObject
function psObjectValueText(v) {
    if (isNull(v)) { return ''; }
    if (Array.isArray(v)) { return 'System.Object[]'; }
    //a nested PSCustomObject's own ToString() is empty
    if (isPSObject(v)) { return ''; }
    return toStr(v);
}

//PowerShell's conversion to string, used for "$value" expansion, [string] casts and -join
export function toStr(v) {
    if (v === null || v === undefined || v === ANULL) { return ''; }
    switch (typeof v) {
        case 'string': return v;
        case 'boolean': return v ? 'True' : 'False';
        case 'number': return formatNumber(v);
        default: break;
    }
    if (isEnumerable(v)) { return toArray(v).map(toStr).join(' '); }
    if (v instanceof PSDate) { return formatDate(v, 'G'); }
    if (v instanceof PSHashtable) { return typeName(v); }
    if (v instanceof TimeSpan) { return formatTimeSpan(v); }
    if (v instanceof PSVersion) { return v.toString(); }
    if (v instanceof StringBuilder) { return v.toString(); }
    if (v instanceof ScriptBlock) { return v.meta.text ?? ''; }
    if (v instanceof RegexMatch) { return v.Value; }
    if (v instanceof PSType) { return v.name; }
    if (v instanceof IPAddress) { return formatIp(v); }
    if (v instanceof ErrorRecord) { return v.error.message; }
    if (v instanceof DictionaryEntry) { return 'System.Collections.DictionaryEntry'; }
    if (v instanceof PSRef) { return 'System.Management.Automation.PSReference'; }
    if (v instanceof NativeObject) { return typeof v.text === 'function' ? v.text() : (v.text ?? v.type); }
    if (isPSObject(v)) {
        const values = Object.values(v);
        return '@{' + objectKeys(v).map((k, i) => `${k}=${psObjectValueText(values[i])}`).join('; ') + '}';
    }
    return String(v);
}

export function formatIp(ip) {
    if (ip.bytes.length === 4) { return ip.bytes.join('.'); }
    const groups = [];
    for (let i = 0; i < 16; i += 2) { groups.push(((ip.bytes[i] << 8) | ip.bytes[i + 1]).toString(16)); }
    //compress the longest run of zero groups
    let best = -1, bestLen = 0;
    for (let i = 0; i < 8;) {
        if (groups[i] !== '0') { i++; continue; }
        let j = i; while (j < 8 && groups[j] === '0') { j++; }
        if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
        i = j;
    }
    if (best < 0) { return groups.join(':'); }
    return groups.slice(0, best).join(':') + '::' + groups.slice(best + bestLen).join(':');
}

export function parseIp(text) {
    const s = String(text ?? '').trim();
    const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
    if (v4) {
        const bytes = v4.slice(1).map(Number);
        if (bytes.some(b => b > 255)) { return null; }
        return new IPAddress(bytes);
    }
    if (!s.includes(':')) {
        //IPAddress.TryParse also accepts a plain number as an IPv4 address
        if (/^\d+$/.test(s) && Number(s) <= 0xffffffff) {
            const n = Number(s);
            return new IPAddress([Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256]);
        }
        return null;
    }
    let addr = s.replace(/%.*$/, '').replace(/^\[|\]$/g, '');
    let tail = [];
    const lastColon = addr.lastIndexOf(':');
    const tailPart = addr.slice(lastColon + 1);
    if (tailPart.includes('.')) {
        const ip4 = parseIp(tailPart);
        if (!ip4) { return null; }
        tail = [((ip4.bytes[0] << 8) | ip4.bytes[1]).toString(16), ((ip4.bytes[2] << 8) | ip4.bytes[3]).toString(16)];
        addr = addr.slice(0, lastColon + 1) + '0';
        addr = addr.slice(0, -1);
        if (addr.endsWith(':') && !addr.endsWith('::')) { addr = addr.slice(0, -1); }
    }
    const halves = addr.split('::');
    if (halves.length > 2) { return null; }
    const head = halves[0] ? halves[0].split(':') : [];
    let rest = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];
    let groups;
    if (halves.length === 2) {
        const fill = 8 - head.length - rest.length - tail.length;
        if (fill < 0) { return null; }
        groups = [...head, ...Array(fill).fill('0'), ...rest, ...tail];
    } else {
        groups = [...head, ...tail];
    }
    if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) { return null; }
    const bytes = [];
    for (const g of groups) { const n = parseInt(g, 16); bytes.push(n >> 8, n & 255); }
    return new IPAddress(bytes);
}

//System.Net.WebUtility.HtmlEncode
export function htmlEncode(text) {
    const s = toStr(text);
    let out = '';
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c <= 62) {
            switch (c) {
                case 60: out += '&lt;'; continue;
                case 62: out += '&gt;'; continue;
                case 34: out += '&quot;'; continue;
                case 39: out += '&#39;'; continue;
                case 38: out += '&amp;'; continue;
                default: out += s[i]; continue;
            }
        }
        if (c >= 160 && c < 256) { out += `&#${c};`; continue; }
        if (c >= 0xd800 && c <= 0xdbff) {
            const low = s.charCodeAt(i + 1);
            if (low >= 0xdc00 && low <= 0xdfff) {
                out += `&#${(c - 0xd800) * 0x400 + (low - 0xdc00) + 0x10000};`;
                i++;
            } else {
                out += '&#65533;';
            }
            continue;
        }
        if (c >= 0xdc00 && c <= 0xdfff) { out += '&#65533;'; continue; }
        out += s[i];
    }
    return out;
}

//System.Uri.EscapeDataString
export function escapeDataString(text) {
    return encodeURIComponent(toStr(text)).replace(/[!'()*]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

//#endregion

//#region truthiness, type tests and casts

export function truthy(v) {
    if (v === null || v === undefined || v === ANULL) { return false; }
    switch (typeof v) {
        case 'boolean': return v;
        case 'number': return v !== 0;
        case 'string': return v.length > 0;
        default: break;
    }
    if (Array.isArray(v)) { return v.length === 0 ? false : v.length === 1 ? truthy(v[0]) : true; }
    if (v instanceof MatchCollection || v instanceof GroupCollection) { return truthy(v.items); }
    return true;
}

//type names normalized for lookups: lowercase, no 'system.' prefix, accelerators resolved
const TYPE_ALIASES = {
    'int': 'int32', 'long': 'int64', 'short': 'int16', 'byte': 'byte', 'uint64': 'uint64', 'ulong': 'uint64', 'uint': 'uint32', 'uint32': 'uint32',
    'bool': 'boolean', 'float': 'single', 'decimal': 'decimal', 'datetime': 'datetime', 'string': 'string', 'char': 'char',
    'double': 'double', 'object': 'object', 'hashtable': 'collections.hashtable', 'ordered': 'collections.specialized.ordereddictionary',
    'pscustomobject': 'management.automation.pscustomobject', 'psobject': 'management.automation.psobject',
    'array': 'array', 'regex': 'text.regularexpressions.regex', 'uri': 'uri', 'guid': 'guid', 'version': 'version',
    'scriptblock': 'management.automation.scriptblock', 'switch': 'management.automation.switchparameter',
    'ref': 'management.automation.psreference', 'void': 'void', 'ipaddress': 'net.ipaddress', 'timespan': 'timespan',
    'datetimeoffset': 'datetimeoffset', 'math': 'math', 'convert': 'convert', 'cultureinfo': 'globalization.cultureinfo',
    'xml': 'xml.xmldocument', 'type': 'type', 'int32': 'int32', 'int64': 'int64', 'boolean': 'boolean', 'single': 'single'
};

export function normType(name) {
    let n = String(name).trim().toLowerCase();
    if (n.startsWith('system.')) { n = n.slice(7); }
    return TYPE_ALIASES[n] ?? n;
}

export function isType(v, rawType) {
    const t = normType(rawType);
    if (t.endsWith('[]')) {
        if (!Array.isArray(v)) { return false; }
        return t === 'object[]';
    }
    switch (t) {
        case 'string': return typeof v === 'string';
        case 'char': return typeof v === 'string' && v.length === 1;
        case 'boolean': return typeof v === 'boolean';
        case 'int32': case 'int64': case 'int16': case 'byte': case 'uint64': case 'uint32':
            return typeof v === 'number' && Number.isInteger(v);
        case 'double': case 'single': case 'decimal': return typeof v === 'number';
        case 'valuetype': return typeof v === 'number' || typeof v === 'boolean' || v instanceof PSDate;
        case 'datetime': return v instanceof PSDate && v.kind !== 'Offset';
        case 'datetimeoffset': return v instanceof PSDate && v.kind === 'Offset';
        case 'timespan': return v instanceof TimeSpan;
        case 'version': return v instanceof PSVersion;
        case 'collections.hashtable': return v instanceof PSHashtable && !v.ordered;
        case 'collections.specialized.ordereddictionary': return v instanceof PSHashtable && v.ordered;
        case 'collections.idictionary': return v instanceof PSHashtable;
        case 'collections.ienumerable': return typeof v === 'string' || isEnumerable(v) || v instanceof PSHashtable;
        case 'collections.icollection': case 'collections.ilist': return isEnumerable(v) || (t === 'collections.icollection' && v instanceof PSHashtable);
        case 'array': case 'object[]': return Array.isArray(v);
        case 'management.automation.pscustomobject': return isPSObject(v);
        case 'management.automation.psobject': return !isNull(v);
        case 'management.automation.scriptblock': return v instanceof ScriptBlock;
        case 'management.automation.errorrecord': return v instanceof ErrorRecord;
        case 'text.regularexpressions.match': return v instanceof RegexMatch;
        case 'net.ipaddress': return v instanceof IPAddress;
        case 'object': return !isNull(v);
        case 'enum': return false;
        default:
            if (t.startsWith('collections.generic.list')) { return Array.isArray(v); }
            if (t.startsWith('collections.generic.hashset')) { return v instanceof PSHashSet; }
            return false;
    }
}

function toVersion(v) {
    if (v instanceof PSVersion) { return v; }
    const s = toStr(v).trim();
    if (!/^\d+(\.\d+){1,3}$/.test(s)) { throw psError(`Cannot convert value "${s}" to type "System.Version".`); }
    return new PSVersion(s.split('.').map(Number));
}

export function tryVersion(s) {
    const t = toStr(s).trim();
    if (!/^\d+(\.\d+){1,3}$/.test(t)) { return null; }
    return new PSVersion(t.split('.').map(Number));
}

function toDateValue(v) {
    if (v instanceof PSDate) { return v.kind === 'Offset' ? new PSDate(v.ms, 'Unspecified', v.ticks) : v; }
    if (typeof v === 'string') {
        const d = parseDate(v);
        if (!d) { throw psError(`Cannot convert value "${v}" to type "System.DateTime".`); }
        return d;
    }
    if (isNull(v)) { return new PSDate(-62135596800000, 'Unspecified'); }
    throw psError(`Cannot convert value "${toStr(v)}" to type "System.DateTime".`);
}

//[type]value
export function cast(rawType, v) {
    let t = normType(rawType);
    if (v === ANULL || v === undefined) { v = null; }
    if (t.endsWith('[]')) {
        const inner = t.slice(0, -2);
        if (v === null) { return null; }
        const items = isEnumerable(v) ? toArray(v) : [v];
        return inner === 'object' ? items.slice() : items.map(x => cast(inner, x));
    }
    switch (t) {
        case 'void': return undefined;
        case 'string': return v === null ? '' : toStr(v);
        case 'char': return v === null ? '\0' : (typeof v === 'number' ? String.fromCharCode(v) : toStr(v).charAt(0));
        case 'boolean': return truthy(v);
        case 'int32': case 'int16': case 'byte': case 'int64': case 'uint64': case 'uint32': {
            const label = { int32: 'System.Int32', int16: 'System.Int16', byte: 'System.Byte', int64: 'System.Int64', uint64: 'System.UInt64', uint32: 'System.UInt32' }[t];
            if (Array.isArray(v) && v.length === 1) { v = v[0]; }
            if (v instanceof PSDate) { throw psError(`Cannot convert the "${toStr(v)}" value of type "System.DateTime" to type "${label}".`); }
            return toInt(v, label);
        }
        case 'double': case 'single': case 'decimal': return toNumber(v);
        case 'datetime': return toDateValue(v);
        case 'version': return v === null ? null : toVersion(v);
        case 'management.automation.pscustomobject': case 'management.automation.psobject': {
            if (v instanceof PSHashtable) {
                const o = {};
                for (const [key, value] of v.map.values()) { o[toStr(key)] = value === ANULL ? null : value; }
                return o;
            }
            return v;
        }
        case 'collections.hashtable': case 'collections.idictionary': {
            if (v instanceof PSHashtable) { return v; }
            if (isPSObject(v)) {
                const h = new PSHashtable(false);
                const values = Object.values(v);
                objectKeys(v).forEach((k, i) => h.set(k, values[i]));
                return h;
            }
            if (v === null) { return null; }
            throw psError(`Cannot convert the "${toStr(v)}" value of type "${typeName(v)}" to type "System.Collections.Hashtable".`);
        }
        case 'collections.specialized.ordereddictionary': {
            if (v instanceof PSHashtable) { const c = v.clone(); c.ordered = true; return c; }
            return v;
        }
        case 'array': return v === null ? null : (isEnumerable(v) ? toArray(v).slice() : [v]);
        case 'management.automation.switchparameter': return truthy(v);
        case 'management.automation.scriptblock': return v;
        case 'net.ipaddress': {
            const ip = parseIp(toStr(v));
            if (!ip) { throw psError(`Cannot convert value "${toStr(v)}" to type "System.Net.IPAddress".`); }
            return ip;
        }
        case 'guid': {
            const s = toStr(v);
            if (!/^[{(]?[0-9a-f]{8}-?([0-9a-f]{4}-?){3}[0-9a-f]{12}[)}]?$/i.test(s)) { throw psError(`Cannot convert value "${s}" to type "System.Guid".`); }
            return s.replace(/[{}()]/g, '').toLowerCase();
        }
        case 'object': return v;
        case 'uri': return toStr(v);
        default:
            if (t.startsWith('collections.generic.list')) { return v === null ? [] : (isEnumerable(v) ? toArray(v).slice() : [v]); }
            throw psError(`Unable to find type [${rawType}].`);
    }
}

//#endregion

//.NET composite formatting: '{0}', '{0:N1}', '{1,5}', '{{' and '}}'
export function compositeFormat(format, args) {
    const fmt = toStr(format);
    let out = '';
    for (let i = 0; i < fmt.length; i++) {
        const c = fmt[i];
        if (c === '{') {
            if (fmt[i + 1] === '{') { out += '{'; i++; continue; }
            const end = fmt.indexOf('}', i);
            if (end < 0) { throw psError('Error formatting a string: Input string was not in a correct format..'); }
            const spec = fmt.slice(i + 1, end);
            const m = /^\s*(\d+)\s*(?:,\s*(-?\d+))?\s*(?::(.*))?$/.exec(spec);
            if (!m) { throw psError('Error formatting a string: Input string was not in a correct format..'); }
            const index = Number(m[1]);
            if (index >= args.length) { throw psError('Error formatting a string: Index (zero based) must be greater than or equal to zero and less than the size of the argument list..'); }
            let value = args[index];
            let text;
            if (typeof value === 'number' && m[3] !== undefined) { text = formatNumberWith(value, m[3]); }
            else if (value instanceof PSDate && m[3] !== undefined) { text = formatDate(value, m[3]); }
            else { text = toStr(value); }
            if (m[2] !== undefined) {
                const width = Number(m[2]);
                text = width < 0 ? text.padEnd(-width) : text.padStart(width);
            }
            out += text;
            i = end;
        } else if (c === '}') {
            if (fmt[i + 1] === '}') { i++; }
            out += '}';
        } else {
            out += c;
        }
    }
    return out;
}

export { isDict };
