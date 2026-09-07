/**
 * Export routes for the reporting service.
 *
 * CWE-778 exception-family fixture for feature 0087. Every handler site is
 * marked `EXPECT: finding` / `EXPECT: clean`; markers sit either as a trailing
 * comment on the handler header or on the comment line immediately above it.
 * EXPECTATIONS.md records the exact line numbers.
 */
import { promises as fs } from "node:fs";
import type { EventEmitter } from "node:events";

import { fetchJson } from "./http";
import { ExportError } from "./errors";
import { logger } from "./logger";

export interface Cursor {
  id: string;
  updatedAt: string;
}

const API_ROOT = "https://reports.internal/api";

export async function readCursor(path: string): Promise<Cursor | null> {
  try {
    const raw = await fs.readFile(path, "utf8");
    return JSON.parse(raw) as Cursor;
  } catch (err) { // EXPECT: finding -- id=ts_swallow -- returns null, records nothing
    return null;
  }
}

export async function writeCursor(path: string, cursor: Cursor): Promise<void> {
  try {
    await fs.writeFile(path, JSON.stringify(cursor), "utf8");
  } catch (err) { // EXPECT: clean -- id=ts_logs -- failure recorded before giving up
    logger.error({ err, path }, "failed to persist export cursor");
  }
}

export async function loadTemplate(name: string): Promise<string> {
  // EXPECT: clean -- id=ts_header_line_log -- defect B1: the entire handler,
  // log call included, sits on the header line.
  try { return await fs.readFile(`templates/${name}.hbs`, "utf8"); } catch (err) { logger.warn({ err, name }, "template missing, falling back to the default"); }
  return "{{body}}";
}

export async function pushBatch(rows: Cursor[]): Promise<void> {
  try {
    await fetchJson(`${API_ROOT}/batch`, { method: "POST", body: rows });
  } catch (err) { // EXPECT: clean -- id=ts_rethrow -- wrapped and propagated
    throw new ExportError(`batch push failed for ${rows.length} rows`, { cause: err });
  }
}

export function parseWindow(raw: string, fallback: number): number {
  try {
    const parsed = Number.parseInt(raw, 10);
    return Number.isNaN(parsed) ? fallback : parsed;
  } catch { // EXPECT: finding -- id=ts_no_binding -- defect B5: ES2019 no-binding catch
    return fallback;
  }
}

export async function readManifest(path: string): Promise<unknown> {
  try {
    return JSON.parse(await fs.readFile(path, "utf8")) as unknown;
  } catch (err) { // EXPECT: finding -- id=ts_scope_leak -- defect B2: the only
    return {};    // nearby log call belongs to reportManifestAge(), not here
  }
}

export function reportManifestAge(manifest: { updatedAt?: string }): void {
  logger.info({ updatedAt: manifest.updatedAt }, "manifest age checked");
}

export async function warmCache(ids: string[]): Promise<void> {
  await Promise.all(
    ids.map((id) =>
      // EXPECT: finding -- id=ts_promise_catch -- `.catch()` collapses the
      // rejection to null with no record.
      fetchJson(`${API_ROOT}/report/${id}`).catch(() => null),
    ),
  );
}

export async function refreshIndex(): Promise<void> {
  // EXPECT: clean -- id=ts_promise_catch_logs -- the rejection handler records it
  await fetchJson(`${API_ROOT}/index/refresh`).catch((err: unknown) => {
    logger.error({ err }, "index refresh rejected");
  });
}

export function subscribe(stream: EventEmitter, sink: string[]): void {
  stream.on("data", (chunk: Buffer) => {
    // EXPECT: finding -- id=ts_then_onrejected -- the onRejected arm of
    // `.then(ok, err)` discards the rejection.
    void fetchJson(`${API_ROOT}/ack`, { method: "POST", body: chunk }).then(
      (ack) => sink.push(String(ack)),
      () => undefined,
    );
  });
}
