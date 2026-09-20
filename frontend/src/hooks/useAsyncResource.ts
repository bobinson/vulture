import { useCallback, useEffect, useRef, useState } from "react";

export interface AsyncResource<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
  /**
   * True when `data` is the last good result of a DIFFERENT key in the same
   * family, held on screen while the current key loads. Always false unless
   * the caller opted in with `family` — see `useAsyncResource`.
   */
  stale: boolean;
  /** Re-run the loader for the current key without changing it. */
  reload: () => void;
}

interface Settled<T> {
  key: string;
  /** The family the key belonged to when it settled, or "" for none. */
  family: string;
  data: T | null;
  error: string | null;
}

export interface AsyncResourceOptions {
  /**
   * Opt in to holding the last good result while a DIFFERENT key of the same
   * family loads, instead of blanking to `null` the instant the key changes.
   *
   * Blanking is right when the key change means "a different thing" (a
   * different finding, a different target). It is wrong when it means "the
   * same thing, re-queried" — a filter or a page change — where it collapses
   * a full table to a placeholder and back for the length of one round trip.
   * The family is what tells those two apart, and it is the CALLER's to name,
   * because only the caller knows which part of its key is the identity.
   */
  family?: string;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Fetch one resource identified by a STRING key.
 *
 * The key — not the loader's object identity — is the dependency, which is
 * what makes a filter change refetch exactly once while a parent re-render
 * that hands down a fresh-but-equal filter object refetches not at all.
 *
 * `loading` is derived (`nothing settled for this key yet`) rather than stored,
 * so the hook never calls setState from inside the effect that starts the
 * request; the only state write is the one that records the outcome.
 *
 * A `null` key means "nothing to load" and is not an error state.
 */
export function useAsyncResource<T>(
  key: string | null,
  load: () => Promise<T>,
  options?: AsyncResourceOptions,
): AsyncResource<T> {
  const family = options?.family ?? "";
  const [settled, setSettled] = useState<Settled<T> | null>(null);
  const [nonce, setNonce] = useState(0);

  // Latest-loader ref, updated in an effect (never during render) so the
  // request effect can depend on the key alone.
  const loadRef = useRef(load);
  useEffect(() => {
    loadRef.current = load;
  });

  useEffect(() => {
    if (key === null) return;
    let live = true;
    // The loader is invoked inside the async IIFE so a SYNCHRONOUS throw
    // (a mocked-out api surface, a bad key) lands in the same catch as a
    // rejected promise instead of escaping the effect.
    void (async () => {
      try {
        const data = await loadRef.current();
        if (live) setSettled({ key, family, data, error: null });
      } catch (err: unknown) {
        if (live) setSettled({ key, family, data: null, error: errorMessage(err) });
      }
    })();
    return () => {
      live = false;
    };
    // `family` is in the deps for correctness, not for extra runs: a caller
    // that changes its family necessarily changes its key too, because the
    // family is the identity part OF the key.
  }, [key, family, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const fresh = settled !== null && settled.key === key;

  // Carry the previous result only when the caller named a family, the
  // previous result belonged to that same family, and it was a SUCCESS: a
  // stale error is not worth looking at, and a stale row from another family
  // would be shown under the wrong heading.
  const carry =
    !fresh &&
    key !== null &&
    family !== "" &&
    settled !== null &&
    settled.family === family &&
    settled.error === null &&
    settled.data !== null;

  const usable = fresh || carry ? settled : null;

  return {
    data: usable === null ? null : usable.data,
    loading: key !== null && !fresh,
    stale: carry,
    error: fresh && settled !== null ? settled.error : null,
    reload,
  };
}
