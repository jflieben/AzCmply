//Native implementations of generated PowerShell functions, used only where the generated code would be needlessly slow.
//Each entry names the hash of the PowerShell function it was written for (meta.h in the generated code). When the
//function changes, the hash no longer matches and the generated implementation is used instead, so an override can
//make things faster but never different.
export default function overrides(R) {
    return {
        //Read-IngestJson reads a file as text and parses it. Ingestion files collected in the browser are held as parsed
        //values, so serializing and parsing them again would only cost time and memory.
        'read-ingestjson': {
            hash: 'f67cbcf749c3df97',
            body: (S, O) => {
                const value = R.vfs.readJson(R.str(S['path']), { dateKind: 'String' });
                O.push(value === undefined ? null : value);
            }
        }
    };
}
