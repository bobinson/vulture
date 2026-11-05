// Feature 0101, CWE-778 Concept A: a try nested inside an anonymous callback.
// The call that receives the callback is NOT the routine declaration; the
// routine name above it is part of the guarded window. Security routines report,
// an ordinary routine with the same wrapper is excused. Identifiers are invented.

export async function rotateSigningKey(id: string) {
  await withLock(id, async () => {
    try {
      await vault.rotate(id);
    } catch (err) { // EXPECT: finding
      return wrapUnknown(err);
    }
  });
}

export function computePasswordHash(plain: string) {
  queue.run(function () {
    try {
      return kdfRunner.run(plain);
    } catch (err) { // EXPECT: finding
      return wrapUnknown(err);
    }
  });
}

export async function renewSessionLease(id: string) {
  return runInSpan('renew', () => {
    try {
      return leases.extend(id);
    } catch (err) { // EXPECT: finding
      return wrapUnknown(err);
    }
  });
}

export async function loadProfileCard(id: string) {
  await withLock(id, async () => {
    try {
      await cards.load(id);
    } catch (err) { // EXPECT: clean
      return wrapUnknown(err);
    }
  });
}

export function renderThumbnail(path: string) {
  queue.run(function () {
    try {
      return images.scale(path);
    } catch (err) { // EXPECT: clean
      return wrapUnknown(err);
    }
  });
}
