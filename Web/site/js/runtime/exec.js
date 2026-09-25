//Execution: scopes, parameter binding, command dispatch, script invocation, errors and the built-in cmdlets.
import {
    ANULL, isNull, PSHashtable, PSDate, ScriptBlock, PSFunction, PSError, ErrorRecord, NamedArg, NativeObject,
    isPSObject, isEnumerable, toArray, objectKeys, findObjectKey, DictionaryEntry
} from './types.js';
import { toStr, truthy, cast, toNumber, typeName } from './convert.js';
import { pipeItems, unwrap, emit, val, eq, ne, gt, ge, lt, le, like, notLike, contains, match, notMatch } from './ops.js';
import { getMember, setBlockInvoker } from './members.js';
import { introSort, psCompare } from './sort.js';
import { parseJson, toJson, toCsv } from './json.js';
import { wildcardRegExp, translate } from './regex.js';
import { isType } from './convert.js';

//#region state

export const state = {
    vfs: null,
    host: { write: t => console.log(t), warn: t => console.warn(t) },
    quietDepth: 0,
    ln: 0,
    files: [],
    overrides: {},
    overrideWarned: new Set()
};

export function positionOf(ln) {
    const index = Math.floor(ln / 100000);
    return { file: state.files[index] ?? '', line: ln % 100000 };
}

export function newScope(parent, isScript = false) {
    const s = Object.create(parent);
    if (isScript) { s['$$script'] = s; }
    return s;
}

export const globalScope = Object.create(null);
globalScope['$$script'] = globalScope;
globalScope['erroractionpreference'] = 'Continue';

export function scriptScope(S) { return S['$$script'] ?? globalScope; }

//#endregion

//#region host output

let pendingLine = '';

function hostWrite(text, noNewline) {
    if (state.quietDepth) { return; }
    if (noNewline) { pendingLine += text; return; }
    state.host.write(pendingLine + text);
    pendingLine = '';
}

export function quietly(fn) {
    state.quietDepth++;
    try { return fn(); } finally { state.quietDepth--; }
}

//#endregion

//#region errors

export function errorRecord(e) {
    if (e instanceof ErrorRecord) { return e; }
    if (!(e instanceof Error)) { e = new PSError(toStr(e)); }
    if (!e.psPosition) { e.psPosition = positionOf(state.ln); }
    return new ErrorRecord(e, e.psPosition);
}

//throw <value>
export function throwValue(v) {
    if (v instanceof ErrorRecord) { return v.error; }
    if (v instanceof Error) { return v; }
    const e = new PSError(isNull(v) ? 'ScriptHalted' : toStr(v), v);
    e.psPosition = positionOf(state.ln);
    return e;
}

//#endregion

//#region parameter binding

const COMMON = new Map([
    ['verbose', true], ['debug', true], ['whatif', true], ['confirm', true],
    ['erroraction', false], ['warningaction', false], ['informationaction', false], ['progressaction', false],
    ['errorvariable', false], ['warningvariable', false], ['informationvariable', false], ['outvariable', false],
    ['outbuffer', false], ['pipelinevariable', false]
]);

function findParam(params, name) {
    const lname = name.toLowerCase();
    let hit = params.find(p => p.ln === lname || (p.al && p.al.includes(lname)));
    if (hit) { return hit; }
    const prefixed = params.filter(p => p.ln.startsWith(lname));
    if (prefixed.length === 1) { return prefixed[0]; }
    if (prefixed.length > 1) { throw new PSError(`Parameter cannot be processed because the parameter name '${name}' is ambiguous. Possible matches include: ${prefixed.map(p => '-' + p.n).join(' ')}.`); }
    return null;
}

//meta.params entries: { n, t (type or null), sw (switch), pos (explicit position or null), def (S => value), al (aliases, lowercase) }
function prepareMeta(meta) {
    if (meta.prepared) { return meta; }
    for (const p of meta.params) { p.ln = p.n.toLowerCase(); }
    const explicit = meta.params.some(p => p.pos !== null && p.pos !== undefined);
    const positional = meta.params.filter(p => !p.sw && (explicit ? p.pos !== null && p.pos !== undefined : true));
    if (explicit) { positional.sort((a, b) => a.pos - b.pos); }
    meta.positional = positional;
    meta.prepared = true;
    return meta;
}

function convertParam(p, v) {
    if (v === ANULL || v === undefined) { v = null; }
    if (p.sw) { return truthy(v); }
    if (!p.t) { return v; }
    return cast(p.t, v);
}

function defaultFor(p) {
    if (p.sw) { return false; }
    if (!p.t) { return null; }
    switch (p.t.toLowerCase().replace(/^system\./, '')) {
        case 'string': return '';
        case 'int': case 'int32': case 'long': case 'int64': case 'double': case 'single': case 'decimal': case 'byte': case 'uint64': return 0;
        case 'bool': case 'boolean': case 'switch': return false;
        default: return null;
    }
}

//binds an argument list to a function's parameters, as variables in scope S; leftovers go to $args
export function bind(meta, S, args, fnName) {
    prepareMeta(meta);
    const params = meta.params;
    const bound = new Map();
    const positional = [];
    const extra = [];
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (!(a instanceof NamedArg)) { positional.push(a); continue; }
        const p = findParam(params, a.name);
        if (!p) {
            const common = COMMON.get(a.name.toLowerCase());
            if (meta.adv && common !== undefined) {
                if (!common && !a.hasValue) { i++; }
                continue;
            }
            if (meta.adv) { throw new PSError(`A parameter cannot be found that matches parameter name '${a.name}'.`); }
            //a simple function passes an unknown parameter and its value on in $args
            extra.push('-' + a.name + (a.hasValue ? ':' : ''));
            if (a.hasValue) { extra.push(a.value); }
            else if (i + 1 < args.length && !(args[i + 1] instanceof NamedArg)) { extra.push(val(args[++i])); }
            continue;
        }
        let value;
        if (p.sw) { value = a.hasValue ? a.value : true; }
        else if (a.hasValue) { value = a.value; }
        else {
            if (i + 1 >= args.length || args[i + 1] instanceof NamedArg) { throw new PSError(`Missing an argument for parameter '${p.n}'. Specify a parameter of type '${p.t ?? 'System.Object'}' and try again.`); }
            value = args[++i];
        }
        if (bound.has(p.ln)) { throw new PSError(`Cannot bind parameter because parameter '${p.n}' is specified more than once.`); }
        bound.set(p.ln, checkedParam(p, value));
    }
    let pi = 0;
    for (const v of positional) {
        while (pi < meta.positional.length && bound.has(meta.positional[pi].ln)) { pi++; }
        if (pi < meta.positional.length) { const p = meta.positional[pi++]; bound.set(p.ln, checkedParam(p, v)); continue; }
        if (meta.adv) { throw new PSError(`A positional parameter cannot be found that accepts argument '${toStr(v)}'.`); }
        extra.push(val(v));
    }
    const missing = params.filter(p => p.mand && !bound.has(p.ln));
    if (missing.length) { throw new PSError(`Cannot process command because of one or more missing mandatory parameters: ${missing.map(p => p.n).join(' ')}.`); }
    //bound values first, then defaults in declaration order (a default may read an earlier parameter)
    for (const p of params) { if (bound.has(p.ln)) { S[p.ln] = bound.get(p.ln); } }
    for (const p of params) {
        if (bound.has(p.ln)) { continue; }
        S[p.ln] = p.def ? convertParam(p, p.def(S)) : defaultFor(p);
    }
    S['args'] = extra;
}

//converts a bound argument and applies the parameter's validation, with PowerShell's messages
function checkedParam(p, value) {
    const raw = value === ANULL || value === undefined ? null : value;
    if (p.mand && !p.allowNull) {
        if (raw === null) { throw new PSError(`Cannot bind argument to parameter '${p.n}' because it is null.`); }
        if (!p.allowEmpty && raw === '' && (!p.t || /^(system\.)?string$/i.test(p.t))) { throw new PSError(`Cannot bind argument to parameter '${p.n}' because it is an empty string.`); }
        if (!p.allowEmpty && Array.isArray(raw) && raw.length === 0) { throw new PSError(`Cannot bind argument to parameter '${p.n}' because it is an empty collection.`); }
    }
    const converted = convertParam(p, value);
    if (p.vs && converted !== null) {
        for (const item of (Array.isArray(converted) ? converted : [converted])) {
            const s = toStr(item);
            if (!p.vs.some(x => x.toLowerCase() === s.toLowerCase())) {
                throw new PSError(`Cannot validate argument on parameter '${p.n}'. The argument "${s}" does not belong to the set "${p.vs.join(',')}" specified by the ValidateSet attribute. Supply an argument that is in the set and then try the command again.`);
            }
        }
    }
    if (p.vp && converted !== null) {
        for (const item of (Array.isArray(converted) ? converted : [converted])) {
            const s = toStr(item);
            if (!new RegExp(translate(p.vp, true).source, 'i').test(s)) {
                throw new PSError(`Cannot validate argument on parameter '${p.n}'. The argument "${s}" does not match the "${p.vp}" pattern. Supply an argument that matches "${p.vp}" and try the command again.`);
            }
        }
    }
    return converted;
}

//#endregion

//#region invocation

export function invokeBlock(sb, callerScope, args, { dot = false, isScript = false, input = null } = {}) {
    const S = dot ? callerScope : newScope(callerScope, isScript);
    bind(sb.meta, S, args);
    if (input !== null) { S['input'] = input; }
    const O = [];
    sb.body(S, O);
    return O;
}

//runs a block in the current scope with $_ set, as ForEach-Object, Where-Object and Sort-Object do
export function runWithItem(sb, S, item, args = []) {
    const had = Object.prototype.hasOwnProperty.call(S, '_');
    const previous = S['_'];
    S['_'] = item;
    try {
        if (sb.meta.params.length || args.length) { bind(sb.meta, S, args); }
        const O = [];
        sb.body(S, O);
        return O;
    } finally {
        if (had) { S['_'] = previous; } else { delete S['_']; }
    }
}

setBlockInvoker((sb, args) => invokeBlock(sb, globalScope, args));

export function defineFunction(S, name, meta, body) {
    const lname = name.toLowerCase();
    const override = state.overrides[lname];
    if (override) {
        if (override.hash === meta.h) { body = override.body; }
        else if (!state.overrideWarned.has(lname)) {
            state.overrideWarned.add(lname);
            state.host.warn(`The browser implementation of ${name} was written for another version of the function; using the generated one.`);
        }
    }
    S['f:' + lname] = new PSFunction(name, new ScriptBlock(meta, body));
}

const ALIASES = {
    '%': 'foreach-object', '?': 'where-object'
};

export function callCommand(S, name, args, input = null) {
    const lname = name.toLowerCase();
    const fn = S['f:' + lname];
    if (fn) {
        const scope = newScope(S);
        bind(fn.block.meta, scope, args, fn.name);
        scope['input'] = input ?? [];
        const O = [];
        fn.block.body(scope, O);
        return O;
    }
    const cmdlet = CMDLETS[ALIASES[lname] ?? lname];
    if (cmdlet) { return runCmdlet(cmdlet, S, args, input); }
    if (/[\\/]|\.ps1$/i.test(name)) { return invokeScriptPath(S, name, args, input, false); }
    throw new PSError(`The term '${name}' is not recognized as a name of a cmdlet, function, script file, or executable program.`);
}

//& target / . target
export function invokeTarget(S, target, args, input = null, dot = false) {
    target = val(target);
    if (target instanceof ScriptBlock) { return invokeBlock(target, S, args, { dot, input }); }
    if (target instanceof PSFunction) { return invokeBlock(target.block, S, args, { dot, input }); }
    if (target instanceof NativeObject && target.type === 'System.Management.Automation.FunctionInfo') { return callCommand(S, target.props.Name, args, input); }
    const name = toStr(target);
    if (state.vfs && state.vfs.entry(name)?.kind === 'script') { return invokeScriptPath(S, name, args, input, dot); }
    if (dot) { throw new PSError(`The term '${name}' is not recognized as a name of a cmdlet, function, script file, or executable program.`); }
    return callCommand(S, name, args, input);
}

export function invokeScriptPath(S, path, args, input, dot) {
    const e = state.vfs.entry(path);
    if (!e || e.kind !== 'script') { throw new PSError(`The term '${path}' is not recognized as a name of a cmdlet, function, script file, or executable program.`); }
    return invokeBlock(e.module, S, args, { dot, isScript: !dot, input });
}

//runs a registered script with named arguments from the host, in a fresh scope below the global one
export function runScript(path, named = {}) {
    const args = Object.entries(named).filter(([, v]) => v !== undefined).map(([k, v]) => new NamedArg(k, v, true));
    return invokeScriptPath(globalScope, path, args, null, false);
}

//#endregion

//#region cmdlet binding

function bindCmdlet(spec, args) {
    const named = {};
    const positional = [];
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (!(a instanceof NamedArg)) { positional.push(a); continue; }
        const lname = a.name.toLowerCase();
        let p = spec.params.find(x => x.ln === lname || x.al?.includes(lname));
        if (!p) {
            const prefixed = spec.params.filter(x => x.ln.startsWith(lname));
            if (prefixed.length === 1) { p = prefixed[0]; }
            else if (prefixed.length > 1) { throw new PSError(`Parameter cannot be processed because the parameter name '${a.name}' is ambiguous.`); }
        }
        if (!p) {
            const common = COMMON.get(lname) ?? [...COMMON.keys()].filter(k => k.startsWith(lname)).map(k => COMMON.get(k))[0];
            if (common === undefined) { throw new PSError(`A parameter cannot be found that matches parameter name '${a.name}'.`); }
            const key = COMMON.has(lname) ? lname : [...COMMON.keys()].find(k => k.startsWith(lname));
            named[key] = common ? (a.hasValue ? a.value : true) : (a.hasValue ? a.value : args[++i]);
            continue;
        }
        if (p.sw) { named[p.ln] = a.hasValue ? truthy(a.value) : true; }
        else { named[p.ln] = a.hasValue ? a.value : args[++i]; }
    }
    return { named, positional };
}

function runCmdlet(spec, S, args, input) {
    if (!spec.prepared) { for (const p of spec.params) { p.ln = p.n.toLowerCase(); } spec.prepared = true; }
    const b = bindCmdlet(spec, args);
    const ea = b.named['erroraction'];
    try {
        return spec.run(S, b, input === null ? null : input) ?? [];
    } catch (e) {
        if (ea && /^(silentlycontinue|ignore)$/i.test(toStr(ea)) && e instanceof PSError) { return []; }
        throw e;
    }
}

function arg(b, name, position) {
    if (Object.prototype.hasOwnProperty.call(b.named, name)) { return b.named[name]; }
    if (position !== undefined && position < b.positional.length) { return b.positional[position]; }
    return undefined;
}

function spec(params, run) {
    return { params: params.map(p => typeof p === 'string' ? { n: p } : p), run };
}

const sw = n => ({ n, sw: true });

//#endregion

//#region cmdlets

//value of a Sort-Object/Group-Object/Where-Object property spec for one item
function propertyValue(S, item, prop) {
    if (prop instanceof ScriptBlock) { return { exists: true, value: unwrap(runWithItem(prop, S, item)) }; }
    if (prop instanceof PSHashtable) {
        const expr = prop.get('expression') ?? prop.get('e');
        return propertyValue(S, item, expr);
    }
    const name = toStr(prop);
    if (isPSObject(item)) {
        const key = findObjectKey(item, name);
        return key === undefined ? { exists: false, value: null } : { exists: true, value: val(item[key]) };
    }
    if (item instanceof PSHashtable) {
        //a hashtable's properties are its .NET members, not its keys
        const lname = name.toLowerCase();
        if (['count', 'keys', 'values', 'isreadonly', 'isfixedsize', 'issynchronized', 'syncroot'].includes(lname)) { return { exists: true, value: getMember(item, name) }; }
        return { exists: false, value: null };
    }
    if (isNull(item)) { return { exists: false, value: null }; }
    const v = getMember(item, name);
    return { exists: v !== null || item instanceof NativeObject || item instanceof DictionaryEntry, value: v };
}

function propertyList(v) {
    if (v === undefined || isNull(v)) { return []; }
    return isEnumerable(v) ? toArray(v) : [v];
}

function sortEntries(S, items, props, descendingAll, caseSensitive) {
    const entries = items.filter(x => !isNull(x)).map(item => {
        const keys = props.length ? props.map(p => {
            const desc = p instanceof PSHashtable && (p.has('descending') || p.has('ascending'))
                ? (p.has('descending') ? truthy(p.get('descending')) : !truthy(p.get('ascending')))
                : descendingAll;
            return { ...propertyValue(S, item, p), desc };
        }) : [{ exists: true, value: item, desc: descendingAll }];
        return { item, keys };
    });
    const cmp = (a, b) => {
        for (let k = 0; k < a.keys.length; k++) {
            const x = a.keys[k], y = b.keys[k];
            let c;
            if (x.exists && y.exists) { c = psCompare(x.value, y.value, caseSensitive) * (x.desc ? -1 : 1); }
            else if (!x.exists && !y.exists) { c = 0; }
            else { c = x.exists ? 1 : -1; }
            if (c !== 0) { return c; }
        }
        return 0;
    };
    introSort(entries, cmp);
    return { entries, cmp };
}

function fileInfo(entry) {
    const leaf = entry.path.split('/').pop();
    const dot = leaf.lastIndexOf('.');
    const utc = new PSDate(entry.mtime || 0, 'Utc');
    const props = {
        Name: leaf, FullName: entry.path, BaseName: entry.isDir || dot <= 0 ? leaf : leaf.slice(0, dot),
        Extension: entry.isDir || dot < 0 ? '' : leaf.slice(dot), DirectoryName: entry.path.slice(0, entry.path.lastIndexOf('/')) || '/',
        LastWriteTimeUtc: utc, LastWriteTime: utc.toLocal(), Length: entry.size, PSIsContainer: entry.isDir, Mode: entry.isDir ? 'd----' : '-a---'
    };
    return new NativeObject(entry.isDir ? 'System.IO.DirectoryInfo' : 'System.IO.FileInfo', props, entry.path);
}

function pathInfo(p) { return new NativeObject('System.Management.Automation.PathInfo', { Path: p, ProviderPath: p }, p); }

function vfs() {
    if (!state.vfs) { throw new PSError('No file system is attached to the runtime.'); }
    return state.vfs;
}

function splitPath(path, b) {
    const p = toStr(path);
    const trimmed = p.replace(/[\\/]+$/, '') || p;
    const i = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'));
    if (b.named.leaf) { return i < 0 ? trimmed : trimmed.slice(i + 1); }
    if (b.named.leafbase) { const leaf = i < 0 ? trimmed : trimmed.slice(i + 1); const d = leaf.lastIndexOf('.'); return d > 0 ? leaf.slice(0, d) : leaf; }
    if (b.named.extension) { const leaf = i < 0 ? trimmed : trimmed.slice(i + 1); const d = leaf.lastIndexOf('.'); return d >= 0 ? leaf.slice(d) : ''; }
    if (b.named.isabsolute) { return /^([\\/]|[A-Za-z]:)/.test(p); }
    if (i < 0) { return ''; }
    if (i === 0) { return trimmed[0]; }
    return trimmed.slice(0, i);
}

const WHERE_OPERATORS = ['eq', 'ne', 'gt', 'ge', 'lt', 'le', 'like', 'notlike', 'match', 'notmatch', 'contains', 'notcontains', 'in', 'notin', 'is', 'isnot', 'not',
    'ceq', 'cne', 'cgt', 'cge', 'clt', 'cle', 'clike', 'cnotlike', 'cmatch', 'cnotmatch', 'ccontains', 'cnotcontains', 'cin', 'cnotin'];

function whereTest(S, op, left, right) {
    const cs = op.startsWith('c') && op !== 'contains';
    const base = cs ? op.slice(1) : op;
    switch (base) {
        case 'eq': return truthy(eq(left, right, cs));
        case 'ne': return truthy(ne(left, right, cs));
        case 'gt': return truthy(gt(left, right, cs));
        case 'ge': return truthy(ge(left, right, cs));
        case 'lt': return truthy(lt(left, right, cs));
        case 'le': return truthy(le(left, right, cs));
        case 'like': return truthy(like(left, right, cs));
        case 'notlike': return truthy(notLike(left, right, cs));
        case 'match': return truthy(match(S, left, right, cs));
        case 'notmatch': return truthy(notMatch(S, left, right, cs));
        case 'contains': return contains(left, right, cs);
        case 'notcontains': return !contains(left, right, cs);
        case 'in': return contains(right, left, cs);
        case 'notin': return !contains(right, left, cs);
        case 'is': return isType(left, toStr(right));
        case 'isnot': return !isType(left, toStr(right));
        case 'not': return !truthy(left);
        default: throw new PSError(`Unsupported Where-Object operator -${op}`);
    }
}

function measure(S, items, b) {
    const prop = arg(b, 'property', 0);
    let values = items.filter(x => !isNull(x));
    if (prop !== undefined) { values = values.map(x => propertyValue(S, x, prop).value).filter(x => !isNull(x)); }
    const out = { Count: values.length, Average: null, Sum: null, Maximum: null, Minimum: null, Property: prop === undefined ? null : toStr(prop) };
    if (b.named.sum || b.named.average) {
        const nums = values.map(toNumber);
        const sum = nums.reduce((a, c) => a + c, 0);
        if (b.named.sum) { out.Sum = sum; }
        if (b.named.average) { out.Average = nums.length ? sum / nums.length : null; }
    }
    if (b.named.maximum || b.named.minimum) {
        const numeric = values.every(v => typeof v === 'number' || (typeof v === 'string' && !Number.isNaN(Number(v))));
        if (values.length) {
            if (numeric) {
                const nums = values.map(toNumber);
                if (b.named.maximum) { out.Maximum = Math.max(...nums); }
                if (b.named.minimum) { out.Minimum = Math.min(...nums); }
            } else {
                const sorted = values.slice();
                introSort(sorted, (x, y) => psCompare(x, y));
                if (b.named.maximum) { out.Maximum = sorted[sorted.length - 1]; }
                if (b.named.minimum) { out.Minimum = sorted[0]; }
            }
        }
    }
    return new NativeObject('Microsoft.PowerShell.Commands.GenericMeasureInfo', out, 'Microsoft.PowerShell.Commands.GenericMeasureInfo');
}

export const CMDLETS = {
    'foreach-object': spec(['Process', 'MemberName', 'Begin', 'End', 'ArgumentList', 'InputObject'], (S, b, input) => {
        const items = input ?? pipeItems(b.named.inputobject);
        let process = b.named.process ?? b.named.membername ?? b.positional[0];
        if (Array.isArray(process) && process.length === 1) { process = process[0]; }
        const out = [];
        if (b.named.begin instanceof ScriptBlock) { emitAll(out, runWithItem(b.named.begin, S, null)); }
        for (const item of items) {
            if (process instanceof ScriptBlock) { emitAll(out, runWithItem(process, S, item)); }
            else if (typeof process === 'string') {
                if (isNull(item)) { continue; }
                emit(out, getMember(item, process));
            } else { throw new PSError('ForEach-Object needs a script block or a member name.'); }
        }
        if (b.named.end instanceof ScriptBlock) { emitAll(out, runWithItem(b.named.end, S, null)); }
        return out;
    }),
    'where-object': spec(['FilterScript', 'Property', 'Value', 'InputObject', ...WHERE_OPERATORS.map(sw)], (S, b, input) => {
        const items = input ?? pipeItems(b.named.inputobject);
        const script = b.named.filterscript ?? (b.positional[0] instanceof ScriptBlock ? b.positional[0] : undefined);
        if (script) { return items.filter(item => truthy(unwrap(runWithItem(script, S, item)))); }
        const property = b.named.property ?? b.positional[0];
        const value = b.named.value ?? b.positional[1];
        const op = WHERE_OPERATORS.find(o => b.named[o]);
        return items.filter(item => {
            const left = propertyValue(S, item, property).value;
            return op ? whereTest(S, op, left, value) : truthy(left);
        });
    }),
    'sort-object': spec(['Property', sw('Descending'), sw('Unique'), sw('CaseSensitive'), sw('Stable'), 'Top', 'Bottom', 'Culture', 'InputObject'], (S, b, input) => {
        const items = input ?? pipeItems(b.named.inputobject);
        const props = propertyList(arg(b, 'property', 0));
        const { entries, cmp } = sortEntries(S, items, props, !!b.named.descending, !!b.named.casesensitive);
        let out = entries;
        if (b.named.unique) { out = entries.filter((e, i) => i === 0 || cmp(entries[i - 1], e) !== 0); }
        if (b.named.top !== undefined) { out = out.slice(0, toNumber(b.named.top)); }
        if (b.named.bottom !== undefined) { out = out.slice(-toNumber(b.named.bottom)); }
        return out.map(e => e.item);
    }),
    'group-object': spec(['Property', sw('NoElement'), sw('AsHashTable'), sw('AsString'), sw('CaseSensitive'), 'Culture', 'InputObject'], (S, b, input) => {
        const items = input ?? pipeItems(b.named.inputobject);
        const props = propertyList(arg(b, 'property', 0));
        const groups = new Map();
        const order = [];
        for (const item of items) {
            if (isNull(item) && props.length) { continue; }
            const values = props.length ? props.map(p => propertyValue(S, item, p).value) : [item];
            const name = values.map(toStr).join(', ');
            const key = b.named.casesensitive ? name : name.toUpperCase();
            let g = groups.get(key);
            if (!g) { g = { name, values, group: [] }; groups.set(key, g); order.push(g); }
            g.group.push(item);
        }
        //PowerShell 7 returns the groups sorted by their values
        const cmp = (x, y) => {
            for (let i = 0; i < x.values.length; i++) { const c = psCompare(x.values[i], y.values[i], !!b.named.casesensitive); if (c) { return c; } }
            return 0;
        };
        introSort(order, cmp);
        if (b.named.ashashtable) {
            const h = new PSHashtable(false);
            for (const g of order) { h.set(b.named.asstring ? g.name : (g.values.length === 1 ? g.values[0] : g.name), g.group); }
            return [h];
        }
        return order.map(g => new NativeObject('Microsoft.PowerShell.Commands.GroupInfo', b.named.noelement
            ? { Count: g.group.length, Name: g.name, Values: g.values }
            : { Count: g.group.length, Name: g.name, Group: g.group, Values: g.values }, 'Microsoft.PowerShell.Commands.GroupInfo'));
    }),
    'select-object': spec(['Property', 'ExpandProperty', 'ExcludeProperty', 'First', 'Last', 'Skip', 'SkipLast', sw('Unique'), 'Index', 'InputObject'], (S, b, input) => {
        let items = input ?? pipeItems(b.named.inputobject);
        if (b.named.unique) {
            const seen = [];
            items = items.filter(x => { if (seen.some(y => psCompare(y, x) === 0 && toStr(y) === toStr(x))) { return false; } seen.push(x); return true; });
        }
        if (b.named.skip !== undefined) { items = items.slice(toNumber(b.named.skip)); }
        if (b.named.skiplast !== undefined) { items = items.slice(0, Math.max(0, items.length - toNumber(b.named.skiplast))); }
        if (b.named.first !== undefined || b.named.last !== undefined) {
            const first = b.named.first !== undefined ? items.slice(0, toNumber(b.named.first)) : [];
            const last = b.named.last !== undefined ? items.slice(Math.max(0, items.length - toNumber(b.named.last))) : [];
            items = b.named.first !== undefined && b.named.last !== undefined ? [...first, ...last] : (b.named.first !== undefined ? first : last);
        }
        if (b.named.index !== undefined) { items = propertyList(b.named.index).map(i => items[toNumber(i)]).filter(x => x !== undefined); }
        if (b.named.expandproperty !== undefined) {
            const out = [];
            for (const item of items) { emit(out, propertyValue(S, item, b.named.expandproperty).value); }
            return out;
        }
        const props = propertyList(arg(b, 'property', 0));
        if (!props.length) { return items; }
        return items.map(item => {
            const o = {};
            for (const p of props) {
                if (p instanceof PSHashtable) {
                    const label = toStr(p.get('name') ?? p.get('n') ?? p.get('label') ?? p.get('l'));
                    o[label] = propertyValue(S, item, p).value;
                } else if (toStr(p) === '*' && isPSObject(item)) { Object.assign(o, item); }
                else { o[toStr(p)] = propertyValue(S, item, p).value; }
            }
            return o;
        });
    }),
    'measure-object': spec(['Property', sw('Sum'), sw('Average'), sw('Maximum'), sw('Minimum'), sw('Line'), sw('Word'), sw('Character'), 'InputObject'], (S, b, input) => [measure(S, input ?? pipeItems(b.named.inputobject), b)]),
    'convertto-json': spec(['InputObject', 'Depth', sw('Compress'), sw('EnumsAsStrings'), sw('AsArray'), 'EscapeHandling'], (S, b, input) => {
        let value;
        if (input !== null) { value = input.length === 1 && !b.named.asarray ? input[0] : input; }
        else { value = val(arg(b, 'inputobject', 0)); if (b.named.asarray && !Array.isArray(value)) { value = [value]; } }
        const depth = b.named.depth !== undefined ? toNumber(b.named.depth) : 2;
        return [toJson(value, { depth, compress: !!b.named.compress, onTruncate: d => hostWarn(`Resulting JSON is truncated as serialization has exceeded the set depth of ${d}.`) })];
    }),
    'convertfrom-json': spec(['InputObject', sw('AsHashtable'), 'Depth', sw('NoEnumerate'), 'DateKind'], (S, b, input) => {
        const text = input !== null ? input.map(toStr).join('\n') : toStr(arg(b, 'inputobject', 0));
        const dateKind = b.named.datekind !== undefined ? toStr(b.named.datekind) : 'Default';
        const value = parseJson(text, { asHashtable: !!b.named.ashashtable, dateKind: /^string$/i.test(dateKind) ? 'String' : 'Default' });
        if (Array.isArray(value) && !b.named.noenumerate) { return value; }
        return [value];
    }),
    'convertto-csv': spec(['InputObject', sw('NoTypeInformation'), sw('IncludeTypeInformation'), 'UseQuotes', 'QuoteFields', 'Delimiter', sw('NoHeader')], (S, b, input) => {
        const items = input ?? pipeItems(b.named.inputobject);
        const quoting = b.named.usequotes !== undefined ? toStr(b.named.usequotes).toLowerCase() : 'always';
        const lines = toCsv(items, { quoting, delimiter: b.named.delimiter !== undefined ? toStr(b.named.delimiter) : ',' });
        return b.named.noheader ? lines.slice(1) : lines;
    }),
    'join-path': spec(['Path', 'ChildPath', 'AdditionalChildPath', sw('Resolve')], (S, b) => {
        const paths = propertyList(arg(b, 'path', 0));
        const child = arg(b, 'childpath', 1);
        const more = [...propertyList(b.named.additionalchildpath), ...b.positional.slice(2)];
        return paths.map(p => {
            let result = toStr(p);
            for (const c of [child, ...more]) {
                if (c === undefined || isNull(c)) { continue; }
                const cs = toStr(c);
                if (!cs) { continue; }
                result = result.replace(/[\\/]+$/, '') + '/' + cs.replace(/^[\\/]+/, '');
            }
            return result.replace(/\\/g, '/');
        });
    }),
    'split-path': spec(['Path', 'LiteralPath', sw('Parent'), sw('Leaf'), sw('LeafBase'), sw('Extension'), sw('Qualifier'), sw('NoQualifier'), sw('IsAbsolute'), sw('Resolve')], (S, b, input) => {
        const paths = input ?? propertyList(b.named.path ?? b.named.literalpath ?? b.positional[0]);
        return paths.map(p => splitPath(p, b));
    }),
    'resolve-path': spec(['Path', 'LiteralPath', sw('Relative')], (S, b) => {
        return propertyList(b.named.path ?? b.named.literalpath ?? b.positional[0]).map(p => {
            const full = vfs().resolve(toStr(p));
            if (!vfs().exists(full)) { throw new PSError(`Cannot find path '${full}' because it does not exist.`); }
            return pathInfo(full);
        });
    }),
    'test-path': spec(['Path', 'LiteralPath', 'PathType', sw('IsValid')], (S, b) => {
        const type = b.named.pathtype !== undefined ? toStr(b.named.pathtype).toLowerCase() : 'any';
        return propertyList(b.named.path ?? b.named.literalpath ?? b.positional[0]).map(p => {
            if (isNull(p) || toStr(p) === '') { throw new PSError(`Cannot bind argument to parameter 'Path' because it is an empty string.`); }
            const s = toStr(p);
            if (type === 'container') { return vfs().isDir(s); }
            if (type === 'leaf') { return vfs().isFile(s); }
            return vfs().exists(s);
        });
    }),
    'get-childitem': spec(['Path', 'Filter', sw('Recurse'), sw('File'), sw('Directory'), 'Include', 'Exclude', sw('Force'), 'Depth', 'LiteralPath', sw('Name')], (S, b) => {
        const paths = propertyList(b.named.path ?? b.named.literalpath ?? b.positional[0]);
        const filter = arg(b, 'filter', 1);
        const re = filter !== undefined ? wildcardRegExp(toStr(filter)) : null;
        const out = [];
        for (const p of (paths.length ? paths : ['.'])) {
            const full = vfs().resolve(toStr(p));
            if (!vfs().exists(full)) { throw new PSError(`Cannot find path '${full}' because it does not exist.`); }
            if (vfs().isFile(full)) { out.push(fileInfo({ ...vfs().entry(full), isDir: false, size: 0 })); continue; }
            for (const e of vfs().list(full, { recurse: !!b.named.recurse })) {
                if (b.named.file && e.isDir) { continue; }
                if (b.named.directory && !e.isDir) { continue; }
                if (re && !re.test(e.path.split('/').pop())) { continue; }
                out.push(b.named.name ? e.path.slice(full.length + 1) : fileInfo(e));
            }
        }
        return out;
    }),
    'get-content': spec(['Path', sw('Raw'), 'Encoding', 'TotalCount', 'LiteralPath'], (S, b) => {
        const out = [];
        for (const p of propertyList(b.named.path ?? b.named.literalpath ?? b.positional[0])) {
            const s = toStr(p);
            if (!vfs().isFile(s)) { throw new PSError(`Cannot find path '${vfs().resolve(s)}' because it does not exist.`); }
            const text = vfs().readText(s);
            if (b.named.raw) { out.push(text); continue; }
            const lines = text.split(/\r?\n/);
            if (lines.length && lines[lines.length - 1] === '') { lines.pop(); }
            out.push(...(b.named.totalcount !== undefined ? lines.slice(0, toNumber(b.named.totalcount)) : lines));
        }
        return out;
    }),
    'new-item': spec(['Path', 'ItemType', 'Name', 'Value', sw('Force')], (S, b) => {
        let path = toStr(arg(b, 'path', 0));
        if (b.named.name !== undefined) { path = path + '/' + toStr(b.named.name); }
        const type = b.named.itemtype !== undefined ? toStr(b.named.itemtype).toLowerCase() : 'file';
        if (type === 'directory') {
            if (vfs().isDir(path) && !b.named.force) { throw new PSError(`An item with the specified name ${vfs().resolve(path)} already exists.`); }
            const full = vfs().mkdir(path);
            return [fileInfo({ path: full, isDir: true, mtime: Date.now(), size: 0 })];
        }
        vfs().writeText(path, b.named.value !== undefined ? toStr(b.named.value) : '');
        return [fileInfo({ ...vfs().entry(path), isDir: false, size: 0 })];
    }),
    'remove-item': spec(['Path', 'LiteralPath', sw('Recurse'), sw('Force')], (S, b) => {
        for (const p of propertyList(b.named.path ?? b.named.literalpath ?? b.positional[0])) {
            const s = toStr(p);
            if (!vfs().exists(s)) { throw new PSError(`Cannot find path '${vfs().resolve(s)}' because it does not exist.`); }
            vfs().remove(s, { recurse: true });
        }
        return [];
    }),
    'expand-archive': spec(['Path', 'DestinationPath', sw('Force'), 'LiteralPath'], () => {
        throw new PSError('Expand-Archive is not available in the browser.');
    }),
    'get-location': spec([], () => [pathInfo(vfs().cwd)]),
    'get-command': spec(['Name', 'CommandType', 'Module'], (S, b) => {
        const name = toStr(arg(b, 'name', 0));
        const lname = name.toLowerCase();
        const fn = S['f:' + lname];
        const cmdlet = CMDLETS[ALIASES[lname] ?? lname];
        if (!fn && !cmdlet) { throw new PSError(`The term '${name}' is not recognized as a name of a cmdlet, function, script file, or executable program.`); }
        const parameters = new PSHashtable(false);
        const list = fn ? fn.block.meta.params.map(p => p.n) : cmdlet.params.map(p => p.n);
        for (const p of list) { parameters.set(p, true); }
        const props = { Name: fn ? fn.name : name, CommandType: fn ? 'Function' : 'Cmdlet', Parameters: parameters };
        if (fn) { props.ScriptBlock = fn.block; }
        return [new NativeObject(fn ? 'System.Management.Automation.FunctionInfo' : 'System.Management.Automation.CmdletInfo', props, name)];
    }),
    'write-host': spec(['Object', sw('NoNewline'), 'Separator', 'ForegroundColor', 'BackgroundColor'], (S, b) => {
        const objects = b.named.object !== undefined ? [b.named.object] : b.positional;
        const sep = b.named.separator !== undefined ? toStr(b.named.separator) : ' ';
        hostWrite(objects.map(o => isEnumerable(o) ? toArray(o).map(toStr).join(sep) : toStr(o)).join(sep), !!b.named.nonewline);
        return [];
    }),
    'write-warning': spec(['Message'], (S, b) => { hostWarn(toStr(arg(b, 'message', 0))); return []; }),
    'out-null': spec(['InputObject'], () => [])
};

function emitAll(out, items) { for (const x of items) { out.push(x); } }

function hostWarn(text) {
    if (state.quietDepth) { return; }
    state.host.warn(text);
}

//#endregion

export { typeName, objectKeys, hostWrite, hostWarn };
