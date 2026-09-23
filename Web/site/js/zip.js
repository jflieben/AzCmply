//Zip writing with the browser's own deflate implementation (CompressionStream), so no library is needed.
//Writes ingestion and history zips the PowerShell module reads.

const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) { c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; }
        table[n] = c >>> 0;
    }
    return table;
})();

function crc32(bytes) {
    let c = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) { c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8); }
    return (c ^ 0xffffffff) >>> 0;
}

async function transform(bytes, stream) {
    const response = new Response(new Blob([bytes]).stream().pipeThrough(stream));
    return new Uint8Array(await response.arrayBuffer());
}

function dosDateTime(date) {
    const time = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
    const day = ((date.getFullYear() - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
    return { time, day };
}

//a zip (as a Blob) of [{ name, text | bytes }]
export async function writeZip(files, date = new Date()) {
    const encoder = new TextEncoder();
    const parts = [];
    const central = [];
    let offset = 0;
    const { time, day } = dosDateTime(date);
    for (const file of files) {
        const content = file.bytes ?? encoder.encode(file.text ?? '');
        const compressed = await transform(content, new CompressionStream('deflate-raw'));
        const name = encoder.encode(file.name);
        const crc = crc32(content);
        const local = new DataView(new ArrayBuffer(30));
        local.setUint32(0, 0x04034b50, true);
        local.setUint16(4, 20, true);
        local.setUint16(6, 0x0800, true);
        local.setUint16(8, 8, true);
        local.setUint16(10, time, true);
        local.setUint16(12, day, true);
        local.setUint32(14, crc, true);
        local.setUint32(18, compressed.length, true);
        local.setUint32(22, content.length, true);
        local.setUint16(26, name.length, true);
        parts.push(new Uint8Array(local.buffer), name, compressed);
        const entry = new DataView(new ArrayBuffer(46));
        entry.setUint32(0, 0x02014b50, true);
        entry.setUint16(4, 20, true);
        entry.setUint16(6, 20, true);
        entry.setUint16(8, 0x0800, true);
        entry.setUint16(10, 8, true);
        entry.setUint16(12, time, true);
        entry.setUint16(14, day, true);
        entry.setUint32(16, crc, true);
        entry.setUint32(20, compressed.length, true);
        entry.setUint32(24, content.length, true);
        entry.setUint16(28, name.length, true);
        entry.setUint32(42, offset, true);
        central.push(new Uint8Array(entry.buffer), name);
        offset += 30 + name.length + compressed.length;
        if (offset > 0xffffffff) { throw new Error('The data is too large for a zip file; download it in parts or use the PowerShell module.'); }
    }
    const centralSize = central.reduce((n, p) => n + p.length, 0);
    const end = new DataView(new ArrayBuffer(22));
    end.setUint32(0, 0x06054b50, true);
    end.setUint16(8, files.length, true);
    end.setUint16(10, files.length, true);
    end.setUint32(12, centralSize, true);
    end.setUint32(16, offset, true);
    return new Blob([...parts, ...central, new Uint8Array(end.buffer)], { type: 'application/zip' });
}
