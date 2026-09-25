//Runs one generated script module on the browser runtime under node and prints its output, one item per line.
//Usage: node run-script.mjs <generated module> <virtual path>
import { pathToFileURL } from 'node:url';
import { R, VFS } from '../site/js/runtime/index.js';

const [modulePath, virtualPath] = process.argv.slice(2);
const vfs = new VFS();
R.configure({ vfs, host: { write: t => console.log(t), warn: t => console.log('WARNING: ' + t) } });
const block = (await import(pathToFileURL(modulePath).href)).default;
vfs.registerScript(virtualPath, block);
try {
    for (const item of R.runScript(virtualPath)) { console.log(R.str(item)); }
} catch (e) {
    console.log('UNHANDLED: ' + (e && e.stack ? e.stack : e));
    process.exitCode = 1;
}
