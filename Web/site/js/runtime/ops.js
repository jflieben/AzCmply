//PowerShell operators.
import {
    ANULL, isNull, PSHashtable, PSHashSet, PSDate, TimeSpan, PSVersion, isEnumerable, toArray, PSError, RegexMatch, ScriptBlock
} from './types.js';
import { toStr, toNumber, parseNumber, truthy, isType, cast, compositeFormat, tryVersion, parseDate } from './convert.js';
import { translate, matchesTable, regexReplace, regexSplit, wildcardRegExp } from './regex.js';

export const collator = new Intl.Collator('en', { sensitivity: 'accent' });
const collatorCase = new Intl.Collator('en', { sensitivity: 'variant', caseFirst: 'upper' });

//#region enumeration

//items a value sends down a pipeline: $null is one item, AutomationNull none, collections their items
export function pipeItems(v) {
    if (v === ANULL || v === undefined) { return []; }
    if (v === null) { return [null]; }
    if (isEnumerable(v)) { return toArray(v); }
    return [v];
}

//items a foreach statement iterates: $null and AutomationNull none
export function foreachItems(v) {
    if (isNull(v)) { return []; }
    if (isEnumerable(v)) { return toArray(v); }
    return [v];
}

//@(value)
export function arrayOf(v) {
    if (v === ANULL || v === undefined) { return []; }
    if (v === null) { return [null]; }
    if (isEnumerable(v)) { return toArray(v).slice(); }
    return [v];
}

//a collection result: none is AutomationNull, one is the item, more is an array
export function unwrap(items) {
    if (items.length === 0) { return ANULL; }
    if (items.length === 1) { return items[0]; }
    return items;
}

//writes a value to an output list, enumerating collections one level
export function emit(O, v) {
    if (v === undefined || v === ANULL) { return; }
    if (isEnumerable(v)) { for (const x of toArray(v)) { O.push(x); } return; }
    O.push(v);
}

//a value about to be stored or passed on: AutomationNull becomes $null
export function val(v) { return v === ANULL || v === undefined ? null : v; }

//#endregion

//#region equality and comparison

function isCollection(v) { return isEnumerable(v); }

function strEq(a, b, cs) { return cs ? a === b : (a === b || a.toLowerCase() === b.toLowerCase()); }

//scalar -eq: the right side is converted to the type of the left side
export function scalarEq(l, r, cs = false) {
    if (isNull(l)) { return isNull(r); }
    if (isNull(r)) { return false; }
    switch (typeof l) {
        case 'string': return strEq(l, toStr(r), cs);
        case 'boolean': return l === truthy(r);
        case 'number': {
            if (typeof r === 'number') { return l === r; }
            if (typeof r === 'boolean') { return l === (r ? 1 : 0); }
            if (typeof r === 'string') { const n = parseNumber(r); return !Number.isNaN(n) && n === l; }
            if (Array.isArray(r) && r.length === 1) { return scalarEq(l, r[0], cs); }
            return false;
        }
        default: break;
    }
    if (l instanceof PSDate) {
        const d = r instanceof PSDate ? r : (typeof r === 'string' ? parseDate(r) : null);
        return !!d && l.ms === d.ms && l.ticks === d.ticks;
    }
    if (l instanceof PSVersion) { const v = r instanceof PSVersion ? r : tryVersion(r); return !!v && l.compare(v) === 0; }
    if (l instanceof TimeSpan) { return r instanceof TimeSpan && l.ms === r.ms; }
    return l === r;
}

export function eq(l, r, cs = false) {
    if (isCollection(l)) { return toArray(l).filter(x => scalarEq(x, r, cs)); }
    return scalarEq(l, r, cs);
}

export function ne(l, r, cs = false) {
    if (isCollection(l)) { return toArray(l).filter(x => !scalarEq(x, r, cs)); }
    return !scalarEq(l, r, cs);
}

//three way comparison with the left operand's type; $null sorts before everything
export function compareValues(l, r, cs = false) {
    const ln = isNull(l), rn = isNull(r);
    if (ln || rn) {
        if (ln && rn) { return 0; }
        if (ln) { return typeof r === 'number' && r < 0 ? 1 : -1; }
        return typeof l === 'number' && l < 0 ? -1 : 1;
    }
    if (typeof l === 'string') {
        const rs = toStr(r);
        return cs ? collatorCase.compare(l, rs) : collator.compare(l, rs);
    }
    if (typeof l === 'number') {
        let rv = r;
        if (typeof r === 'string') {
            rv = parseNumber(r);
            if (Number.isNaN(rv)) { throw new PSError(`Cannot convert value "${r}" to type "System.Int32". Error: "The input string '${r}' was not in a correct format."`); }
        } else if (typeof r === 'boolean') { rv = r ? 1 : 0; }
        else if (typeof r !== 'number') { rv = toNumber(r); }
        return l < rv ? -1 : l > rv ? 1 : 0;
    }
    if (typeof l === 'boolean') { const rb = truthy(r); return l === rb ? 0 : (l ? 1 : -1); }
    if (l instanceof PSDate) {
        const d = r instanceof PSDate ? r : parseDate(toStr(r));
        if (!d) { throw new PSError(`Cannot convert value "${toStr(r)}" to type "System.DateTime".`); }
        return l.compare(d);
    }
    if (l instanceof PSVersion) { return l.compare(r instanceof PSVersion ? r : cast('version', r)); }
    if (l instanceof TimeSpan) { const rv = r instanceof TimeSpan ? r.ms : toNumber(r) / 10000; return l.ms < rv ? -1 : l.ms > rv ? 1 : 0; }
    const ls = toStr(l), rs = toStr(r);
    return collator.compare(ls, rs);
}

function relational(l, r, test, cs) {
    if (isCollection(l)) { return toArray(l).filter(x => test(compareScalar(x, r, cs))); }
    return test(compareScalar(l, r, cs));
}

//-gt/-lt with $null: $null is below every value, and nothing is above $null except values
function compareScalar(l, r, cs) { return compareValues(l, r, cs); }

export const gt = (l, r, cs) => relational(l, r, c => c > 0, cs);
export const ge = (l, r, cs) => relational(l, r, c => c >= 0, cs);
export const lt = (l, r, cs) => relational(l, r, c => c < 0, cs);
export const le = (l, r, cs) => relational(l, r, c => c <= 0, cs);

export function contains(collection, value, cs = false) {
    for (const x of pipeItemsForContains(collection)) { if (scalarEq(x, value, cs)) { return true; } }
    return false;
}

function pipeItemsForContains(v) {
    if (v === ANULL || v === undefined) { return []; }
    if (v === null) { return [null]; }
    if (isEnumerable(v)) { return toArray(v); }
    return [v];
}

export const inOp = (value, collection, cs) => contains(collection, value, cs);

//#endregion

//#region pattern operators

//-match: sets $Matches in the given scope for a scalar that matches
export function match(S, l, pattern, cs = false) {
    const t = translate(toStr(pattern), !cs);
    const re = new RegExp(t.source, t.flags);
    if (isCollection(l)) { return toArray(l).filter(x => re.test(toStr(x))); }
    const m = re.exec(toStr(l));
    if (!m) { return false; }
    S['matches'] = matchesTable(m, t);
    return true;
}

export function notMatch(S, l, pattern, cs = false) {
    const t = translate(toStr(pattern), !cs);
    const re = new RegExp(t.source, t.flags);
    if (isCollection(l)) { return toArray(l).filter(x => !re.test(toStr(x))); }
    const m = re.exec(toStr(l));
    if (m) { S['matches'] = matchesTable(m, t); }
    return !m;
}

export function like(l, pattern, cs = false) {
    const re = wildcardRegExp(toStr(pattern), !cs);
    if (isCollection(l)) { return toArray(l).filter(x => re.test(toStr(x))); }
    return re.test(toStr(l));
}

export function notLike(l, pattern, cs = false) {
    const re = wildcardRegExp(toStr(pattern), !cs);
    if (isCollection(l)) { return toArray(l).filter(x => !re.test(toStr(x))); }
    return !re.test(toStr(l));
}

//-replace: right side is the pattern, or (pattern, replacement); replacement may be a scriptblock
export function replace(l, r, cs = false, invokeBlock) {
    let pattern, replacement = '';
    if (Array.isArray(r)) {
        if (r.length > 2) { throw new PSError('The -replace operator allows only two elements to follow it, not ' + r.length + '.'); }
        pattern = r[0]; replacement = r.length > 1 ? r[1] : '';
    } else { pattern = r; }
    const one = x => {
        if (replacement instanceof ScriptBlock) { return regexReplace(toStr(x), toStr(pattern), null, !cs, m => toStr(invokeBlock(replacement, m))); }
        return regexReplace(toStr(x), toStr(pattern), toStr(replacement), !cs);
    };
    if (isCollection(l)) { return toArray(l).map(one); }
    return one(l);
}

//binary -split: right side is the pattern, or (pattern, max substrings)
export function split(l, r, cs = false) {
    let pattern = r, count = 0;
    if (Array.isArray(r)) { pattern = r[0]; count = r.length > 1 ? Number(toNumber(r[1])) : 0; }
    const pieces = [];
    for (const x of (isCollection(l) ? toArray(l) : [l])) {
        if (pattern instanceof ScriptBlock) { throw new PSError('-split with a scriptblock is not supported.'); }
        pieces.push(...regexSplit(toStr(x), toStr(pattern), !cs, count));
    }
    return pieces;
}

//unary -split: on whitespace, empty entries removed
export function splitUnary(v) {
    const pieces = [];
    for (const x of (isCollection(v) ? toArray(v) : [v])) { pieces.push(...toStr(x).trim().split(/\s+/).filter(Boolean)); }
    return pieces;
}

export function join(l, sep) {
    if (isNull(l)) { return ''; }
    if (isCollection(l)) { return toArray(l).map(toStr).join(toStr(sep)); }
    return toStr(l);
}

export function joinUnary(v) { return join(v, ''); }

//#endregion

//#region arithmetic

function plainNumber(v) {
    if (typeof v === 'number') { return v; }
    if (typeof v === 'boolean') { return v ? 1 : 0; }
    return toNumber(v);
}

export function add(l, r) {
    if (l === ANULL) { l = null; }
    if (isNull(l)) {
        if (r === ANULL || r === undefined) { return null; }
        return r;
    }
    if (isCollection(l)) {
        const items = toArray(l).slice();
        if (r === ANULL || r === undefined) { return items; }
        if (isCollection(r)) { items.push(...toArray(r)); } else { items.push(r); }
        return items;
    }
    if (l instanceof PSHashtable) {
        if (!(r instanceof PSHashtable)) { throw new PSError('A hash table can only be added to another hash table.'); }
        const c = l.clone();
        for (const [k, v] of r.map.values()) { c.add(k, v); }
        return c;
    }
    if (typeof l === 'string') { return l + toStr(r); }
    if (l instanceof PSDate) {
        if (r instanceof TimeSpan) { return l.addMs(r.ms); }
        return l.addTicks(plainNumber(r));
    }
    if (l instanceof TimeSpan) { return new TimeSpan(l.ms + (r instanceof TimeSpan ? r.ms : plainNumber(r) / 10000)); }
    if (isNull(r)) { return plainNumber(l); }
    return plainNumber(l) + plainNumber(r);
}

export function sub(l, r) {
    if (l instanceof PSDate) {
        if (r instanceof PSDate) { return new TimeSpan((l.ms - r.ms) + (l.ticks - r.ticks) / 10000); }
        if (r instanceof TimeSpan) { return l.addMs(-r.ms); }
    }
    if (l instanceof TimeSpan && r instanceof TimeSpan) { return new TimeSpan(l.ms - r.ms); }
    return plainNumber(isNull(l) ? 0 : l) - plainNumber(isNull(r) ? 0 : r);
}

export function mul(l, r) {
    if (typeof l === 'string') { return l.repeat(Math.max(0, plainNumber(r))); }
    if (isCollection(l)) {
        const items = toArray(l), n = plainNumber(r), out = [];
        for (let i = 0; i < n; i++) { out.push(...items); }
        return out;
    }
    return plainNumber(isNull(l) ? 0 : l) * plainNumber(isNull(r) ? 0 : r);
}

export function div(l, r) {
    const d = plainNumber(isNull(r) ? 0 : r);
    if (d === 0) { throw new PSError('Attempted to divide by zero.'); }
    return plainNumber(isNull(l) ? 0 : l) / d;
}

export function mod(l, r) {
    const d = plainNumber(isNull(r) ? 0 : r);
    if (d === 0) { throw new PSError('Attempted to divide by zero.'); }
    return plainNumber(isNull(l) ? 0 : l) % d;
}

export function neg(v) { return -plainNumber(isNull(v) ? 0 : v); }

//bitwise operators on 64-bit values
function big(v) { return BigInt(Math.trunc(plainNumber(isNull(v) ? 0 : v))); }
export function band(l, r) { return Number(big(l) & big(r)); }
export function bor(l, r) { return Number(big(l) | big(r)); }
export function bxor(l, r) { return Number(big(l) ^ big(r)); }
export function bnot(v) { return Number(~big(v)); }
export function shl(l, r) { return Number(big(l) << big(r)); }
export function shr(l, r) { return Number(big(l) >> big(r)); }

export function range(a, b) {
    const from = Math.trunc(plainNumber(a)), to = Math.trunc(plainNumber(b));
    const out = [];
    if (from <= to) { for (let i = from; i <= to; i++) { out.push(i); } }
    else { for (let i = from; i >= to; i--) { out.push(i); } }
    return out;
}

export function format(fmt, args) { return compositeFormat(fmt, isCollection(args) ? toArray(args) : [args]); }

export function is(v, type) { return isType(v, type); }

//#endregion

export { truthy, RegexMatch, PSHashSet };
