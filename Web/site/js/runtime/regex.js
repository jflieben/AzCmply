//.NET regular expressions and PowerShell wildcards on the JS regex engine.
import { PSError, PSHashtable, RegexMatch } from './types.js';

const cache = new Map();

//translates a .NET pattern; returns { source, flags, groups } where groups lists the JS capture groups in order
//with their .NET number and name
export function translate(pattern, ignoreCase, multiline = false, singleline = false) {
    const key = `${ignoreCase ? 'i' : ''}${multiline ? 'm' : ''}${singleline ? 's' : ''}|${pattern}`;
    let entry = cache.get(key);
    if (entry) { return entry; }
    let p = String(pattern);
    //leading inline options
    const lead = /^\(\?([imsxn]+)(?:-([imsxn]+))?\)/.exec(p);
    if (lead) {
        if (lead[1].includes('i')) { ignoreCase = true; }
        if (lead[1].includes('m')) { multiline = true; }
        if (lead[1].includes('s')) { singleline = true; }
        if (lead[2]?.includes('i')) { ignoreCase = false; }
        p = p.slice(lead[0].length);
    }
    let out = '';
    let needsUnicode = false;
    const groups = [];
    let inClass = false;
    for (let i = 0; i < p.length; i++) {
        const c = p[i];
        if (c === '\\') {
            const n = p[i + 1];
            if (n === undefined) { throw new PSError(`Invalid pattern '${pattern}': illegal \\ at end of pattern.`); }
            if (!inClass && n === 'A') { out += multiline ? '(?<![\\s\\S])' : '^'; i++; continue; }
            if (!inClass && n === 'z') { out += '(?![\\s\\S])'; i++; continue; }
            if (!inClass && n === 'Z') { out += '(?=\\n?(?![\\s\\S]))'; i++; continue; }
            if (n === 'e') { out += '\\x1B'; i++; continue; }
            if (n === 'p' || n === 'P') { needsUnicode = true; }
            if (n === 'G') { throw new PSError(`Unsupported regular expression construct \\G in '${pattern}'`); }
            out += c + n;
            i++;
            continue;
        }
        if (inClass) {
            if (c === '[' && p[i + 1] === ':') { out += '\\['; continue; }
            if (c === '-' && p[i + 1] === '[') { throw new PSError(`Unsupported character class subtraction in '${pattern}'`); }
            if (c === ']') { inClass = false; }
            out += c;
            continue;
        }
        if (c === '[') {
            inClass = true;
            out += c;
            if (p[i + 1] === '^') { out += '^'; i++; }
            if (p[i + 1] === ']') { out += '\\]'; i++; }
            continue;
        }
        if (c === '$') { out += multiline ? '(?=\\n|(?![\\s\\S]))' : '(?=\\n?(?![\\s\\S]))'; continue; }
        if (c === '(') {
            if (p[i + 1] !== '?') { groups.push({ name: null }); out += c; continue; }
            const rest = p.slice(i + 2);
            let m;
            if (rest.startsWith('#')) { const end = p.indexOf(')', i); i = end; continue; }
            if ((m = /^<([A-Za-z_][A-Za-z0-9_]*)>/.exec(rest)) || (m = /^'([A-Za-z_][A-Za-z0-9_]*)'/.exec(rest)) || (m = /^P<([A-Za-z_][A-Za-z0-9_]*)>/.exec(rest))) {
                groups.push({ name: m[1] });
                out += `(?<${m[1]}>`;
                i += 1 + m[0].length;
                continue;
            }
            if (rest.startsWith('>')) { out += '(?:'; i += 2; continue; }
            if ((m = /^([imsxn]*)(?:-([imsxn]*))?:/.exec(rest)) && (m[1] || m[2] !== undefined)) {
                //scoped options: case follows the pattern default, the rest is not supported by the engine
                out += '(?:';
                i += 1 + m[0].length;
                continue;
            }
            if ((m = /^([imsxn]+)(?:-([imsxn]+))?\)/.exec(rest))) {
                if (m[1].includes('i')) { ignoreCase = true; }
                i += 1 + m[0].length;
                continue;
            }
            out += c;
            continue;
        }
        out += c;
    }
    //.NET numbers unnamed groups first, then named groups in order of appearance
    let number = 1;
    for (const g of groups) { if (!g.name) { g.number = number++; } }
    const nameNumbers = new Map();
    for (const g of groups) {
        if (g.name) {
            if (/^\d+$/.test(g.name)) { g.number = Number(g.name); continue; }
            if (!nameNumbers.has(g.name)) { nameNumbers.set(g.name, number++); }
            g.number = nameNumbers.get(g.name);
        }
    }
    const flags = (ignoreCase ? 'i' : '') + (multiline ? 'm' : '') + (singleline ? 's' : '') + (needsUnicode ? 'u' : '');
    let source = out;
    if (needsUnicode) { source = source.replace(/\\([^A-Za-z0-9\\^$.*+?()[\]{}|\/-])/g, '$1'); }
    try { new RegExp(source, flags); }
    catch (e) { throw new PSError(`Invalid pattern '${pattern}': ${e.message}`); }
    entry = { source, flags, groups };
    cache.set(key, entry);
    return entry;
}

//all matches, advancing past empty matches like .NET
export function matchAll(input, pattern, ignoreCase) {
    const t = translate(pattern, ignoreCase);
    const re = new RegExp(t.source, t.flags + 'g');
    return { matches: Array.from(String(input).matchAll(re)), t };
}

//value of a .NET group number in a JS match
function groupValue(m, t, number) {
    if (number === 0) { return m[0]; }
    for (let i = 0; i < t.groups.length; i++) {
        if (t.groups[i].number === number && m[i + 1] !== undefined) { return m[i + 1]; }
    }
    return undefined;
}

//$Matches for a successful match: group numbers and names of the groups that took part
export function matchesTable(m, t) {
    const h = new PSHashtable(false);
    h.set(0, m[0]);
    for (let i = 0; i < t.groups.length; i++) {
        const g = t.groups[i];
        if (m[i + 1] === undefined) { continue; }
        if (g.name && !/^\d+$/.test(g.name)) { h.set(g.name, m[i + 1]); } else { h.set(g.number, m[i + 1]); }
    }
    return h;
}

//expands a .NET replacement string for one match
export function expandReplacement(replacement, m, t, input) {
    const r = String(replacement);
    if (!r.includes('$')) { return r; }
    const maxGroup = t.groups.reduce((max, g) => Math.max(max, g.number), 0);
    let out = '';
    for (let i = 0; i < r.length; i++) {
        const c = r[i];
        if (c !== '$' || i === r.length - 1) { out += c; continue; }
        const n = r[i + 1];
        if (n === '$') { out += '$'; i++; continue; }
        if (n === '&') { out += m[0]; i++; continue; }
        if (n === '`') { out += input.slice(0, m.index); i++; continue; }
        if (n === "'") { out += input.slice(m.index + m[0].length); i++; continue; }
        if (n === '_') { out += input; i++; continue; }
        if (n === '+') {
            let last = '';
            for (let g = t.groups.length - 1; g >= 0; g--) { if (m[g + 1] !== undefined) { last = m[g + 1]; break; } }
            out += last; i++; continue;
        }
        if (n === '{') {
            const end = r.indexOf('}', i);
            if (end > 0) {
                const name = r.slice(i + 2, end);
                if (/^\d+$/.test(name)) {
                    const v = groupValue(m, t, Number(name));
                    if (Number(name) <= maxGroup) { out += v ?? ''; i = end; continue; }
                } else {
                    const g = t.groups.findIndex(x => x.name === name);
                    if (g >= 0) { out += m[g + 1] ?? ''; i = end; continue; }
                }
            }
            out += c;
            continue;
        }
        if (/\d/.test(n)) {
            //longest digit run that names an existing group
            let j = i + 1;
            while (j < r.length && /\d/.test(r[j])) { j++; }
            let digits = r.slice(i + 1, j);
            while (digits.length && Number(digits) > maxGroup) { digits = digits.slice(0, -1); }
            if (digits.length) {
                out += groupValue(m, t, Number(digits)) ?? '';
                i += digits.length;
                continue;
            }
        }
        out += c;
    }
    return out;
}

export function regexReplace(input, pattern, replacement, ignoreCase, evaluator) {
    const s = String(input);
    const { matches, t } = matchAll(s, pattern, ignoreCase);
    if (!matches.length) { return s; }
    let out = '', last = 0;
    for (const m of matches) {
        out += s.slice(last, m.index);
        out += evaluator ? evaluator(new RegexMatch(m, t.groups)) : expandReplacement(replacement, m, t, s);
        last = m.index + m[0].length;
    }
    return out + s.slice(last);
}

//Regex.Split: pieces between matches plus captured groups in group number order
export function regexSplit(input, pattern, ignoreCase, count = 0) {
    const s = String(input);
    const { matches, t } = matchAll(s, pattern, ignoreCase);
    if (!matches.length || count === 1) { return [s]; }
    const order = t.groups.map((g, i) => ({ number: g.number, index: i })).sort((a, b) => a.number - b.number);
    const result = [];
    let prev = 0, pieces = 0;
    for (const m of matches) {
        if (count > 0 && pieces >= count - 1) { break; }
        result.push(s.slice(prev, m.index));
        pieces++;
        for (const g of order) { if (m[g.index + 1] !== undefined) { result.push(m[g.index + 1]); } }
        prev = m.index + m[0].length;
    }
    result.push(s.slice(prev));
    return result;
}

const likeCache = new Map();

//PowerShell wildcard pattern (-like, switch -Wildcard, -Filter) as an anchored regex
export function wildcardRegExp(pattern, ignoreCase = true) {
    const key = (ignoreCase ? 'i' : 'c') + pattern;
    let re = likeCache.get(key);
    if (re) { return re; }
    let src = '^';
    const p = String(pattern);
    for (let i = 0; i < p.length; i++) {
        const c = p[i];
        if (c === '`' && i + 1 < p.length) { src += escapeRegExp(p[++i]); continue; }
        if (c === '*') { src += '[\\s\\S]*'; continue; }
        if (c === '?') { src += '[\\s\\S]'; continue; }
        if (c === '[') {
            const end = p.indexOf(']', i + 1);
            if (end > i + 1) {
                const body = p.slice(i + 1, end).replace(/\\/g, '\\\\').replace(/\^/g, '\\^');
                src += '[' + body + ']';
                i = end;
                continue;
            }
        }
        src += escapeRegExp(c);
    }
    re = new RegExp(src + '$', ignoreCase ? 'i' : '');
    likeCache.set(key, re);
    return re;
}

export function escapeRegExp(s) { return String(s).replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&'); }

//[regex]::Escape
export function dotnetEscape(s) {
    return String(s).replace(/[\\*+?|{[()^$.#\s]/g, c => {
        switch (c) { case '\n': return '\\n'; case '\r': return '\\r'; case '\t': return '\\t'; case '\f': return '\\f'; case ' ': return '\\ '; default: return '\\' + c; }
    });
}
