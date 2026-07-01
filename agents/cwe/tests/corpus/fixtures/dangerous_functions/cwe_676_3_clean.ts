const DID_RE = /^did:toto:([a-f0-9]{40})$/;
export function parseDid(uri: string): string | null {
    const m = DID_RE.exec(uri);
    return m ? m[1] : null;
}
