//Member access, indexing, instance methods and static members with PowerShell semantics.
import {
    ANULL, isNull, PSHashtable, PSHashSet, PSDate, TimeSpan, PSVersion, IPAddress, PSType, PSRef, RegexMatch, StringBuilder,
    ScriptBlock, DictionaryEntry, ErrorRecord, PSError, NativeObject, MatchCollection, GroupCollection, isPSObject,
    isEnumerable, toArray, objectKeys, findObjectKey, INT_KEY, normKey
} from './types.js';
import {
    toStr, toNumber, toInt, typeName, formatDate, formatNumberWith, formatNumber, mathRound, parseDate, htmlEncode,
    escapeDataString, parseIp, formatIp, tryVersion, cast, normType, roundEven, formatTimeSpan, compositeFormat, truthy
} from './convert.js';
import { translate, matchAll, regexReplace, regexSplit, dotnetEscape } from './regex.js';
import { val } from './ops.js';

const hasOwn = Object.prototype.hasOwnProperty;

//#region member access

function psObjectView(obj) {
    let properties;
    if (isPSObject(obj)) {
        const values = Object.values(obj);
        properties = objectKeys(obj).map((name, i) => noteProperty(name, values[i]));
    } else if (obj instanceof PSHashtable) {
        properties = [['IsReadOnly', false], ['IsFixedSize', false], ['IsSynchronized', false], ['Keys', obj.keys()], ['Values', obj.values()], ['SyncRoot', obj], ['Count', obj.size]]
            .map(([n, v]) => new NativeObject('System.Management.Automation.PSProperty', { Name: n, Value: v, MemberType: 'Property', IsSettable: false }, n));
    } else if (obj instanceof NativeObject) {
        properties = Object.keys(obj.props).map(n => noteProperty(n, obj.props[n]));
    } else {
        properties = [];
    }
    return new NativeObject('System.Management.Automation.PSObject', { Properties: properties, BaseObject: obj, TypeNames: [typeName(obj)] }, () => toStr(obj));
}

function noteProperty(name, value) {
    return new NativeObject('System.Management.Automation.PSNoteProperty', { Name: name, Value: value, MemberType: 'NoteProperty', IsSettable: true, TypeNameOfValue: typeName(value) }, () => `${name}=${toStr(value)}`);
}

function datePart(d, lname) {
    const p = d.parts();
    switch (lname) {
        case 'year': return p.y; case 'month': return p.mo; case 'day': return p.d; case 'hour': return p.h;
        case 'minute': return p.mi; case 'second': return p.s; case 'millisecond': return p.ms;
        case 'dayofweek': return ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'][p.dow];
        case 'dayofyear': return Math.floor((Date.UTC(p.y, p.mo - 1, p.d) - Date.UTC(p.y, 0, 1)) / 86400000) + 1;
        case 'kind': return d.kind === 'Offset' ? undefined : d.kind;
        case 'ticks': return d.totalTicks;
        case 'date': return PSDate.fromParts(p.y, p.mo, p.d, 0, 0, 0, 0, d.kind === 'Offset' ? 'Unspecified' : d.kind);
        case 'utcdatetime': return d.toUniversal();
        case 'localdatetime': return d.toLocal();
        case 'datetime': return d.kind === 'Offset' ? PSDate.fromParts(p.y, p.mo, p.d, p.h, p.mi, p.s, p.ms, 'Unspecified') : d;
        case 'offset': return new TimeSpan(d.offsetMinutes() * 60000);
        case 'timeofday': return new TimeSpan(((p.h * 60 + p.mi) * 60 + p.s) * 1000 + p.ms);
        default: return undefined;
    }
}

function timeSpanPart(t, lname) {
    const ms = t.ms, abs = Math.abs(ms), sign = ms < 0 ? -1 : 1;
    switch (lname) {
        case 'totaldays': return ms / 86400000; case 'totalhours': return ms / 3600000; case 'totalminutes': return ms / 60000;
        case 'totalseconds': return ms / 1000; case 'totalmilliseconds': return ms;
        case 'days': return sign * Math.floor(abs / 86400000); case 'hours': return sign * (Math.floor(abs / 3600000) % 24);
        case 'minutes': return sign * (Math.floor(abs / 60000) % 60); case 'seconds': return sign * (Math.floor(abs / 1000) % 60);
        case 'milliseconds': return sign * (Math.floor(abs) % 1000); case 'ticks': return Math.round(ms * 10000);
        default: return undefined;
    }
}

function groupObject(m, t, index) {
    if (index === 0) {
        return new NativeObject('System.Text.RegularExpressions.Group', { Value: m[0], Success: true, Index: m.index, Length: m[0].length, Name: '0' }, m[0]);
    }
    const g = t.groups[index - 1];
    const v = m[index];
    return new NativeObject('System.Text.RegularExpressions.Group', { Value: v ?? '', Success: v !== undefined, Length: (v ?? '').length, Name: g.name ?? String(g.number) }, v ?? '');
}

//the Groups of a match, in .NET group number order
function groupsOf(match) {
    const m = match.m;
    const t = { groups: match.groupNames };
    const order = t.groups.map((g, i) => ({ g, i: i + 1 })).sort((a, b) => a.g.number - b.g.number);
    const items = [groupObject(m, t, 0), ...order.map(o => groupObject(m, t, o.i))];
    return new GroupCollection(items, items.map(x => x.props.Name));
}

//$obj.name: properties, dictionary keys, intrinsic Count/Length, and member enumeration over collections
export function getMember(obj, name) {
    if (obj === null || obj === undefined || obj === ANULL) {
        const lname = name.toLowerCase();
        return lname === 'count' || lname === 'length' ? 0 : null;
    }
    if (typeof obj === 'object') {
        const proto = Object.getPrototypeOf(obj);
        if (proto === Object.prototype || proto === null) {
            if (hasOwn.call(obj, name)) { const v = obj[name]; return v === undefined ? null : v; }
            const key = findObjectKey(obj, name);
            if (key !== undefined) { const v = obj[key]; return v === undefined ? null : v; }
            const lname = name.toLowerCase();
            if (lname === 'psobject') { return psObjectView(obj); }
            if (lname === 'count' || lname === 'length') { return 1; }
            return null;
        }
        if (Array.isArray(obj)) { return enumerateMember(obj, name); }
    }
    const lname = name.toLowerCase();
    switch (typeof obj) {
        case 'string':
            if (lname === 'length') { return obj.length; }
            if (lname === 'count') { return 1; }
            if (lname === 'psobject') { return psObjectView(obj); }
            return null;
        case 'number': case 'boolean':
            if (lname === 'count' || lname === 'length') { return 1; }
            if (lname === 'psobject') { return psObjectView(obj); }
            return null;
        default: break;
    }
    if (obj instanceof PSHashtable) {
        if (obj.has(name)) { return obj.get(name); }
        switch (lname) {
            case 'count': return obj.size;
            case 'keys': return obj.keys();
            case 'values': return obj.values();
            case 'isreadonly': case 'isfixedsize': case 'issynchronized': return false;
            case 'syncroot': return obj;
            case 'psobject': return psObjectView(obj);
            default: return null;
        }
    }
    if (obj instanceof NativeObject) {
        if (hasOwn.call(obj.props, name)) { return val(obj.props[name]); }
        for (const k of Object.keys(obj.props)) { if (k.toLowerCase() === lname) { return val(obj.props[k]); } }
        if (lname === 'psobject') { return psObjectView(obj); }
        if (lname === 'count' || lname === 'length') { return 1; }
        return null;
    }
    if (obj instanceof PSDate) { const v = datePart(obj, lname); if (v !== undefined) { return v; } }
    if (obj instanceof TimeSpan) { const v = timeSpanPart(obj, lname); if (v !== undefined) { return v; } }
    if (obj instanceof DictionaryEntry) {
        if (lname === 'key' || lname === 'name') { return obj.Key; }
        if (lname === 'value') { return obj.Value; }
    }
    if (obj instanceof PSVersion) {
        const i = ['major', 'minor', 'build', 'revision'].indexOf(lname);
        if (i >= 0) { return i < obj.parts.length ? obj.parts[i] : -1; }
    }
    if (obj instanceof IPAddress && lname === 'addressfamily') { return obj.family; }
    if (obj instanceof RegexMatch) {
        switch (lname) {
            case 'value': return obj.Value; case 'index': return obj.Index; case 'length': return obj.Length;
            case 'success': return true; case 'groups': return groupsOf(obj); case 'name': return '0';
            case 'captures': return new MatchCollection([obj]);
            default: break;
        }
    }
    if (obj instanceof StringBuilder && lname === 'length') { return obj.toString().length; }
    if (obj instanceof ErrorRecord) { return errorRecordMember(obj, lname); }
    if (obj instanceof PSType) {
        if (lname === 'name') {
            const generic = obj.name.indexOf('`');
            const plain = generic >= 0 ? obj.name.slice(0, obj.name.indexOf('[', generic)) : obj.name;
            return plain.slice(plain.lastIndexOf('.', plain.endsWith('[]') ? plain.length - 3 : plain.length) + 1);
        }
        if (lname === 'fullname') { return obj.name; }
    }
    if (obj instanceof PSRef && lname === 'value') { return obj.get(); }
    if (obj instanceof ScriptBlock) {
        if (lname === 'file') { return obj.meta.file ?? null; }
        return null;
    }
    if (obj instanceof GroupCollection && lname === 'count') { return obj.items.length; }
    if (obj instanceof MatchCollection && lname === 'count') { return obj.items.length; }
    if (obj instanceof PSHashSet && lname === 'count') { return obj.size; }
    if (obj instanceof Uint8Array && (lname === 'count' || lname === 'length')) { return obj.length; }
    if (isEnumerable(obj)) { return enumerateMember(toArray(obj), name); }
    if (lname === 'psobject') { return psObjectView(obj); }
    if (lname === 'count' || lname === 'length') { return 1; }
    return null;
}

//member enumeration: the member of every element, collections flattened one level
function enumerateMember(items, name) {
    const lname = name.toLowerCase();
    if (lname === 'count' || lname === 'length' || lname === 'longlength') { return items.length; }
    if (lname === 'rank') { return 1; }
    if (lname === 'issynchronized' || lname === 'isreadonly') { return false; }
    if (lname === 'isfixedsize') { return true; }
    const out = [];
    for (const item of items) {
        if (item === null || item === undefined || item === ANULL) { continue; }
        let v;
        if (isPSObject(item) || item instanceof PSHashtable) {
            v = getMember(item, name);
        } else if (typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean') {
            //.NET values only contribute members they really have
            if (lname === 'length' && typeof item === 'string') { v = item.length; } else { continue; }
        } else {
            v = getMember(item, name);
            if (v === null && !(item instanceof NativeObject)) { continue; }
        }
        if (isEnumerable(v)) { out.push(...toArray(v)); } else { out.push(v); }
    }
    return out.length === 0 ? null : out.length === 1 ? out[0] : out;
}

function errorRecordMember(rec, lname) {
    const e = rec.error;
    switch (lname) {
        case 'exception': return new NativeObject(e instanceof PSError ? 'System.Management.Automation.RuntimeException' : 'System.Exception', { Message: e.message, InnerException: null }, e.message);
        case 'invocationinfo': return new NativeObject('System.Management.Automation.InvocationInfo', {
            ScriptLineNumber: rec.position?.line ?? 0, ScriptName: rec.position?.file ?? '', Line: '', PositionMessage: ''
        });
        case 'errordetails': return null;
        case 'targetobject': return e.target ?? null;
        case 'categoryinfo': return new NativeObject('System.Management.Automation.ErrorCategoryInfo', { Category: 'NotSpecified', Reason: e.name }, 'NotSpecified');
        case 'fullyqualifiederrorid': return e instanceof PSError ? 'RuntimeException' : e.name;
        case 'scriptstacktrace': return '';
        default: return null;
    }
}

export function setMember(obj, name, value) {
    value = val(value);
    if (isNull(obj)) { throw new PSError(`The property '${name}' cannot be found on this object. Verify that the property exists and can be set.`); }
    if (obj instanceof PSHashtable) { obj.set(name, value); return; }
    if (isPSObject(obj)) {
        const key = findObjectKey(obj, name);
        if (key === undefined) { throw new PSError(`Exception setting "${name}": "The property '${name}' cannot be found on this object. Verify that the property exists and can be set."`); }
        obj[key] = value;
        return;
    }
    if (obj instanceof NativeObject) {
        const key = Object.keys(obj.props).find(k => k.toLowerCase() === name.toLowerCase()) ?? name;
        obj.props[key] = value;
        return;
    }
    if (obj instanceof PSRef && name.toLowerCase() === 'value') { obj.set(value); return; }
    throw new PSError(`'${name}' is a ReadOnly property.`);
}

//#endregion

//#region indexing

function indexOne(obj, key) {
    if (Array.isArray(obj)) {
        let i = typeof key === 'number' ? key : toInt(key);
        if (i < 0) { i += obj.length; }
        return i >= 0 && i < obj.length ? val(obj[i]) : null;
    }
    if (obj instanceof PSHashtable) { return obj.get(key); }
    if (typeof obj === 'string') {
        let i = toInt(key);
        if (i < 0) { i += obj.length; }
        return i >= 0 && i < obj.length ? obj[i] : null;
    }
    if (obj instanceof MatchCollection) { const i = toInt(key); return obj.items[i < 0 ? i + obj.items.length : i] ?? null; }
    if (obj instanceof GroupCollection) {
        if (typeof key === 'string' && !/^\d+$/.test(key)) { const i = obj.names.indexOf(key); return i < 0 ? null : obj.items[i]; }
        return obj.items[toInt(key)] ?? null;
    }
    if (obj instanceof Uint8Array) { const i = toInt(key); return obj[i < 0 ? i + obj.length : i] ?? null; }
    if (obj instanceof PSHashSet) { return indexOne(obj.items(), key); }
    if (isPSObject(obj)) { const k = findObjectKey(obj, toStr(key)); return k === undefined ? null : val(obj[k]); }
    if (obj instanceof NativeObject) { return getMember(obj, toStr(key)); }
    //a scalar is its own first element
    const i = toInt(key);
    return i === 0 || i === -1 ? obj : null;
}

export function index(obj, key) {
    if (isNull(obj)) { throw new PSError('Cannot index into a null array.'); }
    if (Array.isArray(key) && !(obj instanceof PSHashtable && obj.has(key))) {
        const out = [];
        for (const k of key) {
            const v = indexOne(obj, k);
            if (v === null && !(obj instanceof PSHashtable)) { continue; }
            out.push(v);
        }
        return out;
    }
    return indexOne(obj, key === ANULL ? null : key);
}

export function setIndex(obj, key, value) {
    value = val(value);
    if (isNull(obj)) { throw new PSError('Cannot index into a null array.'); }
    if (obj instanceof PSHashtable) { obj.set(key, value); return; }
    if (Array.isArray(obj)) {
        let i = toInt(key);
        if (i < 0) { i += obj.length; }
        if (i < 0 || i >= obj.length) { throw new PSError('Index was outside the bounds of the array.'); }
        obj[i] = value;
        return;
    }
    if (isPSObject(obj)) { setMember(obj, toStr(key), value); return; }
    throw new PSError(`Unable to index into an object of type ${typeName(obj)}.`);
}

//#endregion

//#region instance methods

function noMethod(obj, name) {
    return new PSError(`Method invocation failed because [${typeName(obj)}] does not contain a method named '${name}'.`);
}

//.NET Object.Equals for the values the runtime uses
function dotnetEquals(a, b) {
    if (a === b) { return true; }
    if (isNull(a) || isNull(b)) { return isNull(a) && isNull(b); }
    if (a instanceof PSDate && b instanceof PSDate) { return a.ms === b.ms && a.ticks === b.ticks; }
    if (a instanceof PSVersion && b instanceof PSVersion) { return a.compare(b) === 0; }
    return false;
}

function trimChars(args) { return args.length ? args.flatMap(a => isEnumerable(a) ? toArray(a).map(toStr) : [toStr(a)]).join('') : null; }

function trimWith(s, chars, start, end) {
    if (chars === null) { return start && end ? s.trim() : start ? s.trimStart() : s.trimEnd(); }
    let a = 0, b = s.length;
    if (start) { while (a < b && chars.includes(s[a])) { a++; } }
    if (end) { while (b > a && chars.includes(s[b - 1])) { b--; } }
    return s.slice(a, b);
}

function comparisonIgnoresCase(arg) { return typeof arg === 'string' && /ignorecase/i.test(arg); }

function stringMethod(s, lname, args, name) {
    switch (lname) {
        case 'tolowerinvariant': case 'tolower': return s.toLowerCase();
        case 'toupperinvariant': case 'toupper': return s.toUpperCase();
        case 'trim': return trimWith(s, trimChars(args), true, true);
        case 'trimstart': return trimWith(s, trimChars(args), true, false);
        case 'trimend': return trimWith(s, trimChars(args), false, true);
        case 'split': {
            let seps = args.length ? args[0] : null;
            let count = Infinity, removeEmpty = false;
            for (const a of args.slice(1)) {
                if (typeof a === 'number') { count = a; } else if (/removeemptyentries/i.test(toStr(a))) { removeEmpty = true; }
            }
            let separators = seps === null ? [' ', '\t', '\n', '\r'] : (isEnumerable(seps) ? toArray(seps).map(toStr) : [toStr(seps)]);
            separators = separators.filter(x => x !== '');
            const parts = [];
            let rest = s;
            if (!separators.length) { return [s]; }
            while (parts.length < count - 1) {
                let best = -1, bestLen = 0;
                for (const sep of separators) {
                    const i = rest.indexOf(sep);
                    if (i >= 0 && (best < 0 || i < best)) { best = i; bestLen = sep.length; }
                }
                if (best < 0) { break; }
                const piece = rest.slice(0, best);
                rest = rest.slice(best + bestLen);
                if (!removeEmpty || piece) { parts.push(piece); }
            }
            if (!removeEmpty || rest) { parts.push(rest); }
            return parts;
        }
        case 'substring': {
            const start = toInt(args[0]);
            if (start < 0 || start > s.length) { throw new PSError(`Exception calling "Substring" with "${args.length}" argument(s): "startIndex cannot be larger than length of string. (Parameter 'startIndex')"`); }
            if (args.length > 1) {
                const len = toInt(args[1]);
                if (len < 0 || start + len > s.length) { throw new PSError(`Exception calling "Substring" with "2" argument(s): "Index and length must refer to a location within the string. (Parameter 'length')"`); }
                return s.substr(start, len);
            }
            return s.slice(start);
        }
        case 'indexof': {
            const ic = comparisonIgnoresCase(args[args.length - 1]);
            const needle = toStr(args[0]);
            const from = args.length > 1 && typeof args[1] === 'number' ? args[1] : 0;
            return ic ? s.toLowerCase().indexOf(needle.toLowerCase(), from) : s.indexOf(needle, from);
        }
        case 'lastindexof': return s.lastIndexOf(toStr(args[0]));
        case 'startswith': return comparisonIgnoresCase(args[1]) ? s.toLowerCase().startsWith(toStr(args[0]).toLowerCase()) : s.startsWith(toStr(args[0]));
        case 'endswith': return comparisonIgnoresCase(args[1]) ? s.toLowerCase().endsWith(toStr(args[0]).toLowerCase()) : s.endsWith(toStr(args[0]));
        case 'contains': return comparisonIgnoresCase(args[1]) ? s.toLowerCase().includes(toStr(args[0]).toLowerCase()) : s.includes(toStr(args[0]));
        case 'replace': {
            const from = toStr(args[0]), to = toStr(args[1]);
            if (from === '') { throw new PSError(`Exception calling "Replace" with "2" argument(s): "String cannot be of zero length. (Parameter 'oldValue')"`); }
            return s.split(from).join(to);
        }
        case 'padleft': return s.padStart(toInt(args[0]), args.length > 1 ? toStr(args[1]) : ' ');
        case 'padright': return s.padEnd(toInt(args[0]), args.length > 1 ? toStr(args[1]) : ' ');
        case 'tostring': return s;
        case 'equals': return comparisonIgnoresCase(args[1]) ? s.toLowerCase() === toStr(args[0]).toLowerCase() : s === args[0];
        case 'compareto': { const o = toStr(args[0]); return s < o ? -1 : s > o ? 1 : 0; }
        case 'tochararray': return s.split('');
        case 'insert': { const i = toInt(args[0]); return s.slice(0, i) + toStr(args[1]) + s.slice(i); }
        case 'remove': { const i = toInt(args[0]); return args.length > 1 ? s.slice(0, i) + s.slice(i + toInt(args[1])) : s.slice(0, i); }
        case 'normalize': return s.normalize();
        case 'gettype': return new PSType('System.String');
        case 'gethashcode': return 0;
        case 'isnormalized': return s === s.normalize();
        default: throw noMethod(s, name);
    }
}

function listMethod(list, lname, args, name) {
    switch (lname) {
        case 'add': list.push(val(args[0])); return undefined;
        case 'addrange': list.push(...(isEnumerable(args[0]) ? toArray(args[0]) : [val(args[0])])); return undefined;
        case 'clear': list.length = 0; return undefined;
        case 'contains': return list.some(x => dotnetEquals(x, args[0]));
        case 'indexof': return list.findIndex(x => dotnetEquals(x, args[0]));
        case 'remove': {
            const i = list.findIndex(x => dotnetEquals(x, args[0]));
            if (i < 0) { return false; }
            list.splice(i, 1);
            return true;
        }
        case 'removeat': list.splice(toInt(args[0]), 1); return undefined;
        case 'insert': list.splice(toInt(args[0]), 0, val(args[1])); return undefined;
        case 'toarray': case 'clone': return list.slice();
        case 'getrange': {
            const i = toInt(args[0]), n = toInt(args[1]);
            if (i < 0 || n < 0 || i + n > list.length) { throw new PSError(`Exception calling "GetRange" with "2" argument(s): "Offset and length were out of bounds for the array or count is greater than the number of elements from index to the end of the source collection."`); }
            return list.slice(i, i + n);
        }
        case 'reverse': list.reverse(); return undefined;
        case 'gettype': return new PSType('System.Object[]');
        case 'getenumerator': return list.slice();
        case 'tostring': return 'System.Object[]';
        default: {
            //method enumeration: call the method on every element
            const out = [];
            for (const item of list) {
                if (isNull(item)) { continue; }
                const r = invokeMethod(item, name, args);
                if (r !== undefined) { if (isEnumerable(r)) { out.push(...toArray(r)); } else { out.push(r); } }
            }
            return out.length === 0 ? undefined : out.length === 1 ? out[0] : out;
        }
    }
}

function hashtableMethod(h, lname, args, name) {
    switch (lname) {
        case 'containskey':
            if (h.ordered) { throw noMethod(h, name); }
            return h.has(args[0]);
        case 'contains': return h.has(args[0]);
        case 'containsvalue': return h.values().some(v => dotnetEquals(v, args[0]));
        case 'add': {
            const existing = h.map.get(normKey(args[0]));
            if (existing) { throw new PSError(`Exception calling "Add" with "2" argument(s): "Item has already been added. Key in dictionary: '${toStr(existing[0])}'  Key being added: '${toStr(args[0])}'"`); }
            h.set(args[0], val(args[1]));
            return undefined;
        }
        case 'remove': h.delete(args[0]); return undefined;
        case 'clear': h.map.clear(); return undefined;
        case 'getenumerator': return h.entries();
        case 'get_keys': return h.keys();
        case 'get_values': return h.values();
        case 'get_item': return h.get(args[0]);
        case 'set_item': h.set(args[0], val(args[1])); return undefined;
        case 'clone': return h.clone();
        case 'gettype': return new PSType(typeName(h));
        case 'tostring': return typeName(h);
        default: throw noMethod(h, name);
    }
}

function dateMethod(d, lname, args, name) {
    const n = () => toNumber(args[0]);
    switch (lname) {
        case 'tostring': return formatDate(d, args.length ? toStr(args[0]) : null);
        case 'touniversaltime': return d.toUniversal();
        case 'tolocaltime': return d.toLocal();
        case 'adddays': return d.addMs(n() * 86400000);
        case 'addhours': return d.addMs(n() * 3600000);
        case 'addminutes': return d.addMs(n() * 60000);
        case 'addseconds': return d.addMs(n() * 1000);
        case 'addmilliseconds': return d.addMs(n());
        case 'addticks': return d.addTicks(n());
        case 'addmonths': case 'addyears': {
            const p = d.parts();
            const months = lname === 'addmonths' ? n() : n() * 12;
            const total = p.y * 12 + (p.mo - 1) + months;
            const y = Math.floor(total / 12), mo = total % 12 + 1;
            const last = new Date(Date.UTC(y, mo, 0)).getUTCDate();
            const r = PSDate.fromParts(y, mo, Math.min(p.d, last), p.h, p.mi, p.s, p.ms, d.kind === 'Offset' ? 'Utc' : d.kind);
            return new PSDate(d.kind === 'Offset' ? r.ms - d.offset * 60000 : r.ms, d.kind, d.ticks, d.offset);
        }
        case 'add': return d.addMs(args[0] instanceof TimeSpan ? args[0].ms : 0);
        case 'subtract': {
            if (args[0] instanceof PSDate) { return new TimeSpan(d.ms - args[0].ms + (d.ticks - args[0].ticks) / 10000); }
            return d.addMs(-(args[0] instanceof TimeSpan ? args[0].ms : 0));
        }
        case 'compareto': return d.compare(args[0]);
        case 'equals': return args[0] instanceof PSDate && d.compare(args[0]) === 0;
        case 'tounixtimeseconds': return Math.floor(d.ms / 1000);
        case 'tounixtimemilliseconds': return d.ms;
        case 'tofiletimeutc': case 'tofiletime': return d.totalTicks - 504911232000000000;
        case 'gettype': return new PSType(typeName(d));
        default: throw noMethod(d, name);
    }
}

function numberMethod(x, lname, args, name) {
    switch (lname) {
        case 'tostring': return args.length && typeof args[0] === 'string' ? formatNumberWith(x, args[0]) : formatNumber(x);
        case 'compareto': { const o = toNumber(args[0]); return x < o ? -1 : x > o ? 1 : 0; }
        case 'equals': return typeof args[0] === 'number' && x === args[0];
        case 'gettype': return new PSType(typeName(x));
        case 'gethashcode': return x | 0;
        default: throw noMethod(x, name);
    }
}

function scriptBlockMethod(sb, lname, args, name, invoke) {
    switch (lname) {
        case 'invoke': return invoke(sb, args);
        case 'invokereturnasis': { const items = invoke(sb, args); return items.length === 0 ? undefined : items.length === 1 ? items[0] : items; }
        case 'tostring': return sb.meta.text ?? '';
        case 'gettype': return new PSType('System.Management.Automation.ScriptBlock');
        case 'getnewclosure': throw new PSError('GetNewClosure is not supported in the browser runtime.');
        default: throw noMethod(sb, name);
    }
}

let blockInvoker = null;
export function setBlockInvoker(fn) { blockInvoker = fn; }

export function invokeMethod(obj, name, args) {
    if (obj === null || obj === undefined || obj === ANULL) { throw new PSError('You cannot call a method on a null-valued expression.'); }
    args = args.map(a => a === ANULL ? null : a);
    const lname = name.toLowerCase();
    switch (typeof obj) {
        case 'string': return stringMethod(obj, lname, args, name);
        case 'number': return numberMethod(obj, lname, args, name);
        case 'boolean':
            if (lname === 'tostring') { return obj ? 'True' : 'False'; }
            if (lname === 'equals') { return obj === args[0]; }
            if (lname === 'gettype') { return new PSType('System.Boolean'); }
            if (lname === 'compareto') { return (obj ? 1 : 0) - (truthy(args[0]) ? 1 : 0); }
            throw noMethod(obj, name);
        default: break;
    }
    if (Array.isArray(obj)) { return listMethod(obj, lname, args, name); }
    if (obj instanceof PSHashtable) { return hashtableMethod(obj, lname, args, name); }
    if (obj instanceof PSHashSet) {
        switch (lname) {
            case 'add': return obj.add(val(args[0]));
            case 'contains': return obj.has(args[0]);
            case 'remove': return obj.delete(args[0]);
            case 'clear': obj.map.clear(); return undefined;
            case 'unionwith': for (const x of (isEnumerable(args[0]) ? toArray(args[0]) : [args[0]])) { obj.add(x); } return undefined;
            case 'exceptwith': for (const x of (isEnumerable(args[0]) ? toArray(args[0]) : [args[0]])) { obj.delete(x); } return undefined;
            case 'toarray': return obj.items();
            case 'gettype': return new PSType(typeName(obj));
            default: throw noMethod(obj, name);
        }
    }
    if (obj instanceof StringBuilder) {
        switch (lname) {
            case 'append': obj.append(args.length ? toStr(args[0]) : ''); return obj;
            case 'appendline': obj.append((args.length ? toStr(args[0]) : '') + '\r\n'); return obj;
            case 'tostring': return obj.toString();
            case 'clear': obj.parts = []; return obj;
            case 'gettype': return new PSType('System.Text.StringBuilder');
            default: throw noMethod(obj, name);
        }
    }
    if (obj instanceof PSDate) { return dateMethod(obj, lname, args, name); }
    if (obj instanceof TimeSpan) {
        switch (lname) {
            case 'tostring': return formatTimeSpan(obj);
            case 'compareto': return obj.ms < args[0].ms ? -1 : obj.ms > args[0].ms ? 1 : 0;
            case 'add': return new TimeSpan(obj.ms + args[0].ms);
            case 'subtract': return new TimeSpan(obj.ms - args[0].ms);
            case 'negate': return new TimeSpan(-obj.ms);
            case 'duration': return new TimeSpan(Math.abs(obj.ms));
            case 'gettype': return new PSType('System.TimeSpan');
            default: throw noMethod(obj, name);
        }
    }
    if (obj instanceof PSVersion) {
        if (lname === 'tostring') { return obj.toString(); }
        if (lname === 'compareto') { return obj.compare(args[0] instanceof PSVersion ? args[0] : cast('version', args[0])); }
        if (lname === 'equals') { return args[0] instanceof PSVersion && obj.compare(args[0]) === 0; }
        throw noMethod(obj, name);
    }
    if (obj instanceof IPAddress) {
        if (lname === 'getaddressbytes') { return obj.bytes.slice(); }
        if (lname === 'tostring') { return formatIp(obj); }
        throw noMethod(obj, name);
    }
    if (obj instanceof ScriptBlock) { return scriptBlockMethod(obj, lname, args, name, blockInvoker); }
    if (obj instanceof RegexMatch) {
        if (lname === 'tostring') { return obj.Value; }
        throw noMethod(obj, name);
    }
    if (obj instanceof NativeObject) {
        const method = obj.props['#' + lname];
        if (typeof method === 'function') { return method(...args); }
        if (lname === 'tostring') { return toStr(obj); }
        if (lname === 'gettype') { return new PSType(obj.type); }
        throw noMethod(obj, name);
    }
    if (isPSObject(obj)) {
        if (lname === 'tostring') { return toStr(obj); }
        if (lname === 'gettype') { return new PSType('System.Management.Automation.PSCustomObject'); }
        if (lname === 'equals') { return obj === args[0]; }
        throw noMethod(obj, name);
    }
    if (obj instanceof Uint8Array) { return listMethod(Array.from(obj), lname, args, name); }
    if (obj instanceof MatchCollection || obj instanceof GroupCollection) { return listMethod(obj.items.slice(), lname, args, name); }
    if (obj instanceof DictionaryEntry && lname === 'tostring') { return 'System.Collections.DictionaryEntry'; }
    if (obj instanceof ErrorRecord && lname === 'tostring') { return obj.error.message; }
    if (lname === 'tostring') { return toStr(obj); }
    if (lname === 'gettype') { return new PSType(typeName(obj)); }
    throw noMethod(obj, name);
}

//#endregion

//#region static members

const INVARIANT = new NativeObject('System.Globalization.CultureInfo', { Name: '' }, '');
const UTF8 = new NativeObject('System.Text.UTF8Encoding', {
    '#getstring': bytes => new TextDecoder('utf-8').decode(Uint8Array.from(isEnumerable(bytes) ? toArray(bytes) : [])),
    '#getbytes': s => Array.from(new TextEncoder().encode(toStr(s)))
}, 'System.Text.UTF8Encoding');

function base64Decode(s) {
    const t = toStr(s).replace(/\s+/g, '');
    if (t.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(t)) {
        throw new PSError(`Exception calling "FromBase64String" with "1" argument(s): "The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters."`);
    }
    const bin = atob(t);
    const out = new Array(bin.length);
    for (let i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
    return out;
}

function base64Encode(bytes) {
    const arr = isEnumerable(bytes) ? toArray(bytes) : [];
    let bin = '';
    for (const b of arr) { bin += String.fromCharCode(b); }
    return btoa(bin);
}

//[math]::Max/Min pick the overload of the first argument: an integer first argument makes it an integer comparison
function mathMinMax(args, pickMax) {
    let [a, b] = args.map(x => toNumber(x));
    if (Number.isInteger(a)) { b = roundEven(b); }
    return pickMax ? Math.max(a, b) : Math.min(a, b);
}

function regexOptions(o) {
    const s = toStr(o).toLowerCase();
    return { ignoreCase: s.includes('ignorecase') };
}

let vfsRef = null;
export function setVfs(vfs) { vfsRef = vfs; }

export function staticMember(typeRaw, name) {
    const t = normType(typeRaw);
    const n = name.toLowerCase();
    switch (t) {
        case 'math': if (n === 'pi') { return Math.PI; } if (n === 'e') { return Math.E; } break;
        case 'datetime':
            if (n === 'utcnow') { return new PSDate(Date.now(), 'Utc'); }
            if (n === 'now') { return new PSDate(Date.now(), 'Local'); }
            if (n === 'today') { const d = new Date(); return PSDate.fromParts(d.getFullYear(), d.getMonth() + 1, d.getDate(), 0, 0, 0, 0, 'Local'); }
            if (n === 'minvalue') { return new PSDate(-62135596800000, 'Unspecified'); }
            if (n === 'maxvalue') { return new PSDate(253402300799999, 'Unspecified', 9999); }
            break;
        case 'datetimeoffset':
            if (n === 'utcnow') { return new PSDate(Date.now(), 'Offset', 0, 0); }
            if (n === 'now') { return new PSDate(Date.now(), 'Offset', 0, -new Date().getTimezoneOffset()); }
            if (n === 'minvalue') { return new PSDate(-62135596800000, 'Offset', 0, 0); }
            break;
        case 'timespan': if (n === 'zero') { return new TimeSpan(0); } break;
        case 'text.encoding': if (n === 'utf8' || n === 'default' || n === 'ascii' || n === 'unicode') { return UTF8; } break;
        case 'globalization.cultureinfo': if (n === 'invariantculture' || n === 'currentculture' || n === 'currentuiculture') { return INVARIANT; } break;
        case 'stringcomparer':
            if (n.endsWith('ignorecase')) { return new NativeObject('System.StringComparer', { ignoreCase: true }, 'System.OrdinalIgnoreCaseComparer'); }
            return new NativeObject('System.StringComparer', { ignoreCase: false }, 'System.OrdinalComparer');
        case 'string': if (n === 'empty') { return ''; } break;
        case 'guid': if (n === 'empty') { return '00000000-0000-0000-0000-000000000000'; } break;
        case 'int32': if (n === 'maxvalue') { return 2147483647; } if (n === 'minvalue') { return -2147483648; } break;
        case 'int64': if (n === 'maxvalue') { return 9223372036854775807; } if (n === 'minvalue') { return -9223372036854775808; } break;
        case 'double': if (n === 'maxvalue') { return Number.MAX_VALUE; } if (n === 'nan') { return NaN; } if (n === 'positiveinfinity') { return Infinity; } break;
        case 'io.path': if (n === 'directoryseparatorchar') { return '/'; } break;
        case 'environment': if (n === 'newline') { return '\r\n'; } break;
        default: break;
    }
    //enum values are represented by their names
    if (/^(globalization\.datetimestyles|stringcomparison|stringsplitoptions|text\.regularexpressions\.regexoptions|datetimekind|midpointrounding|io\.compression\.compressionlevel|uriformat)$/.test(t)) { return name; }
    throw new PSError(`Unable to find static member '${name}' on type [${typeRaw}].`);
}

export function staticMethod(typeRaw, name, args) {
    const t = normType(typeRaw);
    const n = name.toLowerCase();
    args = args.map(a => a === ANULL ? null : a);
    if (n === 'new') { return construct(t, typeRaw, args); }
    switch (t) {
        case 'math':
            switch (n) {
                case 'abs': return Math.abs(toNumber(args[0]));
                case 'ceiling': return Math.ceil(toNumber(args[0]));
                case 'floor': return Math.floor(toNumber(args[0]));
                case 'truncate': return Math.trunc(toNumber(args[0]));
                case 'max': return mathMinMax(args, true);
                case 'min': return mathMinMax(args, false);
                case 'pow': return Math.pow(toNumber(args[0]), toNumber(args[1]));
                case 'sqrt': return Math.sqrt(toNumber(args[0]));
                case 'round': return mathRound(toNumber(args[0]), args.length > 1 && typeof args[1] === 'number' ? args[1] : 0, args.find(a => typeof a === 'string'));
                case 'sign': return Math.sign(toNumber(args[0]));
                case 'log': return args.length > 1 ? Math.log(toNumber(args[0])) / Math.log(toNumber(args[1])) : Math.log(toNumber(args[0]));
                case 'log10': return Math.log10(toNumber(args[0]));
                case 'exp': return Math.exp(toNumber(args[0]));
                default: break;
            }
            break;
        case 'datetime':
            if (n === 'parse') {
                const d = parseDate(toStr(args[0]));
                if (!d) { throw new PSError(`Exception calling "Parse" with "${args.length}" argument(s): "String '${toStr(args[0])}' was not recognized as a valid DateTime."`); }
                return d;
            }
            if (n === 'specifykind') { return new PSDate(args[0].ms, toStr(args[1]), args[0].ticks); }
            break;
        case 'datetimeoffset':
            if (n === 'parse') {
                const assumeUniversal = args.slice(1).some(a => /assumeuniversal/i.test(toStr(a)));
                const d = parseDate(toStr(args[0]), { assumeUniversal, offsetResult: true });
                if (!d) { throw new PSError(`Exception calling "Parse" with "${args.length}" argument(s): "The string '${toStr(args[0])}' was not recognized as a valid DateTime. There is an unknown word starting at index '0'."`); }
                return d;
            }
            if (n === 'tryparse') {
                const ref = args[args.length - 1];
                const assumeUniversal = args.slice(1, -1).some(a => /assumeuniversal/i.test(toStr(a)));
                const d = isNull(args[0]) ? null : parseDate(toStr(args[0]), { assumeUniversal, offsetResult: true });
                if (ref instanceof PSRef) { ref.set(d ?? new PSDate(-62135596800000, 'Offset', 0, 0)); }
                return !!d;
            }
            if (n === 'fromunixtimeseconds') { return new PSDate(toNumber(args[0]) * 1000, 'Offset', 0, 0); }
            if (n === 'fromunixtimemilliseconds') { return new PSDate(toNumber(args[0]), 'Offset', 0, 0); }
            break;
        case 'timespan':
            if (n === 'fromdays') { return new TimeSpan(toNumber(args[0]) * 86400000); }
            if (n === 'fromhours') { return new TimeSpan(toNumber(args[0]) * 3600000); }
            if (n === 'fromminutes') { return new TimeSpan(toNumber(args[0]) * 60000); }
            if (n === 'fromseconds') { return new TimeSpan(toNumber(args[0]) * 1000); }
            break;
        case 'convert':
            if (n === 'frombase64string') { return base64Decode(args[0]); }
            if (n === 'tobase64string') { return base64Encode(args[0]); }
            if (n === 'tohexstring') { return toArray(args[0]).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase(); }
            if (n === 'toint32' || n === 'toint64') { return args.length > 1 ? parseInt(toStr(args[0]), toNumber(args[1])) : toInt(args[0]); }
            if (n === 'tostring') { return toStr(args[0]); }
            break;
        case 'io.file':
            if (n === 'exists') { return vfsRef.isFile(toStr(args[0])); }
            if (n === 'readalltext') { return vfsRef.readText(toStr(args[0])); }
            if (n === 'writealltext') { vfsRef.writeText(toStr(args[0]), toStr(args[1])); return undefined; }
            if (n === 'readalllines') { return vfsRef.readText(toStr(args[0])).split(/\r?\n/); }
            if (n === 'delete') { vfsRef.remove(toStr(args[0])); return undefined; }
            break;
        case 'io.directory':
            if (n === 'exists') { return vfsRef.isDir(toStr(args[0])); }
            if (n === 'createdirectory') { vfsRef.mkdir(toStr(args[0])); return undefined; }
            break;
        case 'io.path': {
            const p = toStr(args[0]);
            const leaf = p.split(/[\\/]/).pop();
            const dot = leaf.lastIndexOf('.');
            if (n === 'getextension') { return dot <= 0 && !(dot === 0 && leaf.length > 1) ? (dot === 0 ? leaf : '') : leaf.slice(dot); }
            if (n === 'getfilenamewithoutextension') { return dot > 0 ? leaf.slice(0, dot) : (dot === 0 ? '' : leaf); }
            if (n === 'getfilename') { return leaf; }
            if (n === 'getdirectoryname') { return p.replace(/[\\/][^\\/]*$/, ''); }
            if (n === 'gettemppath') { return '/tmp/'; }
            if (n === 'combine') { return vfsRef.join(...args.map(toStr)); }
            if (n === 'getfullpath') { return vfsRef.resolve(p); }
            break;
        }
        case 'net.ipaddress':
            if (n === 'tryparse') {
                const ip = isNull(args[0]) ? null : parseIp(toStr(args[0]));
                if (args[1] instanceof PSRef) { args[1].set(ip); }
                return !!ip;
            }
            if (n === 'parse') {
                const ip = parseIp(toStr(args[0]));
                if (!ip) { throw new PSError(`Exception calling "Parse" with "1" argument(s): "An invalid IP address was specified."`); }
                return ip;
            }
            break;
        case 'net.webutility':
            if (n === 'htmlencode') { return isNull(args[0]) ? null : htmlEncode(args[0]); }
            if (n === 'urlencode') { return encodeURIComponent(toStr(args[0])).replace(/%20/g, '+'); }
            break;
        case 'xml.xmlconvert':
            if (n === 'totimespan') { return isoDuration(toStr(args[0])); }
            break;
        case 'uri':
            if (n === 'escapedatastring') { return escapeDataString(args[0]); }
            if (n === 'unescapedatastring') { return decodeURIComponent(toStr(args[0])); }
            break;
        case 'guid':
            if (n === 'newguid') { return globalThis.crypto.randomUUID(); }
            if (n === 'parse') { return cast('guid', args[0]); }
            break;
        case 'text.regularexpressions.regex': {
            const opt = args.length > 2 ? regexOptions(args[args.length - 1]) : { ignoreCase: false };
            if (n === 'matches') {
                const o = args.length > 2 ? regexOptions(args[2]) : { ignoreCase: false };
                const { matches, t: tr } = matchAll(toStr(args[0]), toStr(args[1]), o.ignoreCase);
                return new MatchCollection(matches.map(m => new RegexMatch(m, tr.groups)));
            }
            if (n === 'match') {
                const o = args.length > 2 ? regexOptions(args[2]) : { ignoreCase: false };
                const { matches, t: tr } = matchAll(toStr(args[0]), toStr(args[1]), o.ignoreCase);
                return matches.length ? new RegexMatch(matches[0], tr.groups) : new NativeObject('System.Text.RegularExpressions.Match', { Success: false, Value: '', Index: 0, Length: 0 }, '');
            }
            if (n === 'ismatch') {
                const o = args.length > 2 ? regexOptions(args[2]) : { ignoreCase: false };
                const tr = translate(toStr(args[1]), o.ignoreCase);
                return new RegExp(tr.source, tr.flags).test(toStr(args[0]));
            }
            if (n === 'replace') {
                const o = args.length > 3 ? regexOptions(args[3]) : { ignoreCase: false };
                if (args[2] instanceof ScriptBlock) {
                    return regexReplace(toStr(args[0]), toStr(args[1]), null, o.ignoreCase, m => toStr(unwrapItems(blockInvoker(args[2], [m]))));
                }
                return regexReplace(toStr(args[0]), toStr(args[1]), toStr(args[2]), o.ignoreCase);
            }
            if (n === 'split') { return regexSplit(toStr(args[0]), toStr(args[1]), opt.ignoreCase); }
            if (n === 'escape') { return dotnetEscape(toStr(args[0])); }
            break;
        }
        case 'version':
            if (n === 'tryparse') {
                const v = tryVersion(args[0]);
                if (args[1] instanceof PSRef) { args[1].set(v); }
                return !!v;
            }
            if (n === 'parse') { return cast('version', args[0]); }
            break;
        case 'string':
            if (n === 'isnullorempty') { return isNull(args[0]) || toStr(args[0]) === ''; }
            if (n === 'isnullorwhitespace') { return isNull(args[0]) || toStr(args[0]).trim() === ''; }
            if (n === 'join') {
                const items = args.length === 2 && isEnumerable(args[1]) ? toArray(args[1]) : args.slice(1);
                return items.map(toStr).join(toStr(args[0]));
            }
            if (n === 'format') { return compositeFormat(args[0], args.length === 2 && isEnumerable(args[1]) ? toArray(args[1]) : args.slice(1)); }
            if (n === 'concat') { return args.map(toStr).join(''); }
            if (n === 'compare') { return toStr(args[0]) < toStr(args[1]) ? -1 : toStr(args[0]) > toStr(args[1]) ? 1 : 0; }
            break;
        case 'char':
            if (n === 'convertfromutf32') { return String.fromCodePoint(toNumber(args[0])); }
            if (n === 'isdigit') { return /^\d$/.test(toStr(args[0]).charAt(0)); }
            if (n === 'isletter') { return /^\p{L}$/u.test(toStr(args[0]).charAt(0)); }
            if (n === 'isletterordigit') { return /^[\p{L}\d]$/u.test(toStr(args[0]).charAt(0)); }
            if (n === 'iswhitespace') { return /^\s$/.test(toStr(args[0]).charAt(0)); }
            if (n === 'isupper') { const c = toStr(args[0]).charAt(0); return c !== c.toLowerCase(); }
            if (n === 'islower') { const c = toStr(args[0]).charAt(0); return c !== c.toUpperCase(); }
            break;
        case 'int32': case 'int64': case 'double':
            if (n === 'tryparse') {
                const s = toStr(args[0]).trim();
                const ok = t === 'double' ? /^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/i.test(s) : /^[+-]?\d+$/.test(s);
                const ref = args[args.length - 1];
                if (ref instanceof PSRef) { ref.set(ok ? Number(s) : 0); }
                return ok;
            }
            if (n === 'parse') { return t === 'double' ? toNumber(args[0]) : toInt(args[0]); }
            break;
        default: break;
    }
    throw new PSError(`Method invocation failed because [${typeRaw}] does not contain a method named '${name}'.`);
}

function unwrapItems(items) { return items.length === 0 ? null : items.length === 1 ? items[0] : items; }

function construct(t, typeRaw, args) {
    if (t.startsWith('collections.generic.list') || t === 'collections.arraylist') {
        return args.length && isEnumerable(args[0]) ? toArray(args[0]).slice() : [];
    }
    if (t.startsWith('collections.generic.hashset')) {
        let ignoreCase = false, items = [];
        for (const a of args) {
            if (a instanceof NativeObject && a.type === 'System.StringComparer') { ignoreCase = a.props.ignoreCase; }
            else if (isEnumerable(a)) { items = toArray(a); }
        }
        const s = new PSHashSet(ignoreCase);
        for (const x of items) { s.add(x); }
        return s;
    }
    if (t === 'collections.hashtable') { return new PSHashtable(false); }
    if (t === 'collections.specialized.ordereddictionary') { return new PSHashtable(true); }
    if (t === 'text.stringbuilder') { return new StringBuilder(args.length && typeof args[0] === 'string' ? args[0] : ''); }
    if (t === 'text.utf8encoding') { return UTF8; }
    if (t === 'datetime') {
        const [y, mo, d, h = 0, mi = 0, s = 0] = args.slice(0, 6).map(x => typeof x === 'number' ? x : toNumber(x));
        const kindArg = args.find(a => typeof a === 'string' && /^(utc|local|unspecified)$/i.test(a));
        const kind = kindArg ? kindArg[0].toUpperCase() + kindArg.slice(1).toLowerCase() : 'Unspecified';
        return PSDate.fromParts(y, mo, d, h, mi, s, 0, kind);
    }
    if (t === 'timespan') {
        const nums = args.map(toNumber);
        if (nums.length === 3) { return new TimeSpan(((nums[0] * 60 + nums[1]) * 60 + nums[2]) * 1000); }
        if (nums.length >= 4) { return new TimeSpan((((nums[0] * 24 + nums[1]) * 60 + nums[2]) * 60 + nums[3]) * 1000 + (nums[4] ?? 0)); }
        return new TimeSpan(nums[0] / 10000);
    }
    if (t === 'version') { return args.length === 1 ? cast('version', args[0]) : new PSVersion(args.map(toInt)); }
    throw new PSError(`Cannot find an overload for "new" on type [${typeRaw}].`);
}

//ISO 8601 duration (XmlConvert.ToTimeSpan)
function isoDuration(s) {
    const m = /^(-)?P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$/.exec(s.trim());
    if (!m || s.trim() === 'P' || /T$/.test(s.trim())) {
        throw new PSError(`Exception calling "ToTimeSpan" with "1" argument(s): "The string '${s}' is not a valid TimeSpan value."`);
    }
    const [, neg, y, mo, d, h, mi, sec] = m;
    const days = Number(y ?? 0) * 365 + Number(mo ?? 0) * 30 + Number(d ?? 0);
    const ms = (((days * 24 + Number(h ?? 0)) * 60 + Number(mi ?? 0)) * 60 + Number(sec ?? 0)) * 1000;
    return new TimeSpan(neg ? -ms : ms);
}

//#endregion

export { INT_KEY };
