//Sort-Object ordering: the .NET introsort (ArraySortHelper, .NET 5+) with PowerShell's value comparison, so equal keys
//end up in the same order as in PowerShell, which does not sort stably.
import { isNull, PSDate, PSVersion, TimeSpan } from './types.js';
import { toStr, toNumber } from './convert.js';
import { collator } from './ops.js';

const INTROSORT_THRESHOLD = 16;

function log2(n) { return 31 - Math.clz32(n); }

export function introSort(keys, cmp) {
    if (keys.length > 1) { introSortRange(keys, 0, keys.length, 2 * (log2(keys.length) + 1), cmp); }
    return keys;
}

function swapIfGreater(a, cmp, i, j) {
    if (cmp(a[i], a[j]) > 0) { const t = a[i]; a[i] = a[j]; a[j] = t; }
}

function swap(a, i, j) { const t = a[i]; a[i] = a[j]; a[j] = t; }

//sorts a[lo, lo + length)
function introSortRange(a, lo, length, depthLimit, cmp) {
    let size = length;
    while (size > 1) {
        if (size <= INTROSORT_THRESHOLD) {
            if (size === 2) { swapIfGreater(a, cmp, lo, lo + 1); return; }
            if (size === 3) {
                swapIfGreater(a, cmp, lo, lo + 1);
                swapIfGreater(a, cmp, lo, lo + 2);
                swapIfGreater(a, cmp, lo + 1, lo + 2);
                return;
            }
            insertionSort(a, lo, size, cmp);
            return;
        }
        if (depthLimit === 0) { heapSort(a, lo, size, cmp); return; }
        depthLimit--;
        const p = pickPivotAndPartition(a, lo, size, cmp);
        introSortRange(a, lo + p + 1, size - (p + 1), depthLimit, cmp);
        size = p;
    }
}

function pickPivotAndPartition(a, lo, size, cmp) {
    const hi = size - 1;
    const middle = hi >> 1;
    swapIfGreater(a, cmp, lo, lo + middle);
    swapIfGreater(a, cmp, lo, lo + hi);
    swapIfGreater(a, cmp, lo + middle, lo + hi);
    const pivot = a[lo + middle];
    swap(a, lo + middle, lo + hi - 1);
    let left = 0, right = hi - 1;
    while (left < right) {
        while (cmp(a[lo + (++left)], pivot) < 0) { /* advance */ }
        while (cmp(pivot, a[lo + (--right)]) < 0) { /* advance */ }
        if (left >= right) { break; }
        swap(a, lo + left, lo + right);
    }
    if (left !== hi - 1) { swap(a, lo + left, lo + hi - 1); }
    return left;
}

function heapSort(a, lo, n, cmp) {
    for (let i = n >> 1; i >= 1; i--) { downHeap(a, lo, i, n, cmp); }
    for (let i = n; i > 1; i--) {
        swap(a, lo, lo + i - 1);
        downHeap(a, lo, 1, i - 1, cmp);
    }
}

function downHeap(a, lo, i, n, cmp) {
    const d = a[lo + i - 1];
    while (i <= n >> 1) {
        let child = 2 * i;
        if (child < n && cmp(a[lo + child - 1], a[lo + child]) < 0) { child++; }
        if (!(cmp(d, a[lo + child - 1]) < 0)) { break; }
        a[lo + i - 1] = a[lo + child - 1];
        i = child;
    }
    a[lo + i - 1] = d;
}

function insertionSort(a, lo, size, cmp) {
    for (let i = 0; i < size - 1; i++) {
        const t = a[lo + i + 1];
        let j = i;
        while (j >= 0 && cmp(t, a[lo + j]) < 0) {
            a[lo + j + 1] = a[lo + j];
            j--;
        }
        a[lo + j + 1] = t;
    }
}

//LanguagePrimitives.CompareObjectToNull: null is above negative numbers and below everything else
function compareToNull(value, nullIsFirst) {
    const i = nullIsFirst ? -1 : 1;
    if (typeof value === 'number') { return value < 0 ? -i : i; }
    return i;
}

//LanguagePrimitives.Compare as used by Sort-Object: strings by culture ignoring case, numbers numerically,
//others through their own comparison, falling back to their string form
export function psCompare(first, second, caseSensitive = false) {
    const fn = isNull(first), sn = isNull(second);
    if (fn) { return sn ? 0 : compareToNull(second, true); }
    if (sn) { return compareToNull(first, false); }
    if (typeof first === 'string') {
        const s = typeof second === 'string' ? second : toStr(second);
        return caseSensitive ? (first < s ? -1 : first > s ? 1 : 0) : collator.compare(first, s);
    }
    if (typeof first === 'number' || typeof first === 'boolean') {
        if (typeof second === 'number' || typeof second === 'boolean') {
            const a = Number(first), b = Number(second);
            return a < b ? -1 : a > b ? 1 : 0;
        }
        try {
            const b = toNumber(second);
            const a = Number(first);
            return a < b ? -1 : a > b ? 1 : 0;
        } catch { return collator.compare(toStr(first), toStr(second)); }
    }
    if (first instanceof PSDate && second instanceof PSDate) { return first.compare(second); }
    if (first instanceof PSVersion && second instanceof PSVersion) { return first.compare(second); }
    if (first instanceof TimeSpan && second instanceof TimeSpan) { return first.ms < second.ms ? -1 : first.ms > second.ms ? 1 : 0; }
    return collator.compare(toStr(first), toStr(second));
}
