// Feature 0101, CWE-778 Concept A inside the security surface: every handler here
// hands its failure on in a way that would excuse it elsewhere, but the guarded
// operation is security-relevant (a credential, signature, key, scope or policy
// check), so the failure is a security event that nothing records. All report.
// Every identifier is invented; the vendor-style call shapes are generic.

export function computePasswordHash(plain: string) {
  try {
    return kdfRunner.run(plain);
  } catch (err) { // EXPECT: finding
    return wrapUnknown(err);
  }
}

export function markAddressVerified(id: string) {
  try {
    return contacts.mark(id);
  } catch (err) { // EXPECT: finding
    return wrapUnknown(err);
  }
}

export function rotateSigningKey(id: string) {
  try {
    return vault.rotate(id);
  } catch (err) { // EXPECT: finding
    return wrapUnknown(err);
  }
}

export function readSessionToken(tok: string) {
  if (tok) {
    try {
      return parseHeader(tok);
    } catch (err) { // EXPECT: finding
      return wrapUnknown(err);
    }
  }
  return null;
}

export function checkEveryToken(tok: string) {
  for (const t of [tok]) {
    try {
      return parseHeader(t);
    } catch (err) { // EXPECT: finding
      return wrapUnknown(err);
    }
  }
  return null;
}

export function sessionKind(k: string) {
  switch (k) {
    case 'a':
      try {
        return parseHeader(k);
      } catch (err) { // EXPECT: finding
        return wrapUnknown(err);
      }
    default:
      return null;
  }
}

export function canRead(user: User, doc: Doc) {
  try {
    policy.enforce(user, 'read', doc);
    return { status: 'ok' };
  } catch (err) { // EXPECT: finding
    return { status: 'denied', error: err };
  }
}

export async function checkAttempt(pw: string, hash: string) {
  let lastError: unknown = null;
  try {
    return await bcrypt.compare(pw, hash);
  } catch (err) { // EXPECT: finding
    lastError = err;
  }
  return lastError === null;
}

export async function findCaller(k: string) {
  try {
    return await keys.findByApiKey(k);
  } catch (e) { // EXPECT: finding
    return wrapUnknown(e);
  }
}

export async function rotateMaster(id: string) {
  let lastErr: unknown = null;
  try {
    await kms.rotate(id);
  } catch (err) { // EXPECT: finding
    lastErr = err;
  }
  return lastErr;
}

export function acceptHook(req: Req, endpointSecret: string) {
  let lastWebhookError: unknown = null;
  try {
    return stripe.webhooks.constructEvent(req.body, req.headers['x-sig'], endpointSecret);
  } catch (err) { // EXPECT: finding
    lastWebhookError = err;
  }
  return lastWebhookError;
}

export function sameMac(a: Buffer, b: Buffer) {
  let lastCompareError: unknown = null;
  try {
    return crypto.timingSafeEqual(a, b);
  } catch (e) { // EXPECT: finding
    lastCompareError = e;
  }
  return lastCompareError === null;
}

export function openEnvelope(ct: Buffer, key: Buffer, iv: Buffer) {
  try {
    const d = crypto.createDecipheriv(ALGO, key, iv);
    return Buffer.concat([d.update(ct), d.final()]);
  } catch (e) { // EXPECT: finding
    return { plaintext: null, error: e };
  }
}

export class ClaimReader {
  read(k: string, t: string) {
    try {
      return Parser.builder().setSigningKey(k).build().parseClaimsJws(t);
    } catch (e) { // EXPECT: finding
      this.lastError = e;
    }
  }

  enforce(c: Claims) {
    try {
      assertAudience(c);
      ensureScope(c, 's');
    } catch (e) { // EXPECT: finding
      this.lastError = e;
    }
  }
}

export async function pinMatches(body: Uint8Array, setError: Setter) {
  try {
    assertDigestMatches(await subtle.digest('SHA-256', body));
  } catch (e) { // EXPECT: finding
    setError(e);
  }
}

export async function currentUser(req: Req) {
  try {
    return await loadPrincipal(req.headers);
  } catch (e) { // EXPECT: finding
    lastError = e;
    return null;
  }
}

export async function checkAttemptQuietly(pw: string, hash: string) {
  try {
    return await bcrypt.compare(pw, hash);
  } catch (e) { // EXPECT: finding
    suppressFailures(); return false;
  }
}

export class AttemptGate {
  async check(pw: string, hash: string) {
    try {
      return await bcrypt.compare(pw, hash);
    } catch (e) { // EXPECT: finding
      this.setFailed(true);
      return false;
    }
  }
}

export function readGrant(raw: string) {
  try {
    return ensureScope(decodeClaims(raw), WRITE_SCOPE);
  } catch (e) { // EXPECT: finding
    metrics.bump(Status.FAILED);
    return null;
  }
}

export function signIn(req: Req, res: Res, uid: string) {
  try {
    return credentials.check(req.body);
  } catch (e) { // EXPECT: finding
    sendFailureResponse(res, 503, Codes.TEMP);
  }
}

export function signInAgain(req: Req, res: Res, uid: string) {
  try {
    return credentials.check(req.body);
  } catch (e) { // EXPECT: finding
    bounceToLogin(res, uid, Errors.TEMP);
  }
}
