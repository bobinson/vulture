// Feature 0101, CWE-778 Concept A outside the security surface.
// A non-empty handler that HANDS THE FAILURE ON (returns it, stores it where it is
// read later, collects it, reports it, forwards it to a callback parameter) records
// it somewhere, so it is not a swallow. Every identifier here is invented.

export async function lookupProfileCard(id: string) {
  try {
    return await cards.fetchCard(id);
  } catch (err) { // EXPECT: clean
    return wrapUnknown(err);
  }
}

export async function healthProbe() {
  try {
    await store.ping();
    return { status: 'healthy' };
  } catch (err) { // EXPECT: clean
    return {
      status: 'unhealthy',
      message: err instanceof Error ? err.message : 'x',
    };
  }
}

export async function pullWithRetry(url: string) {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < RETRY_CEILING; attempt++) {
    try {
      return await netGet(url);
    } catch (error) { // EXPECT: clean
      lastError = error;
      await pause(attempt);
    }
  }
  throw lastError;
}

export function collectOutcomes(jobs: Job[]) {
  const results: Outcome[] = [];
  for (const job of jobs) {
    try {
      results.push({ id: job.id, value: runJob(job) });
    } catch (error) { // EXPECT: clean
      results.push({ id: job.id, reason: error.message });
    }
  }
  return results;
}

export function readSetting(input: string) {
  try {
    return parseSetting(input);
  } catch (e) { // EXPECT: clean
    recordLookupMiss('readSetting', input, e);
    return undefined;
  }
}

export class ReportView {
  async refresh() {
    try {
      this.rows = await reports.list();
    } catch (error) { // EXPECT: clean
      this.errorMessage = error.message;
    }
  }
}

export function readConfigFile(path: string, cb: Callback) {
  try {
    cb(null, JSON.parse(readText(path)));
  } catch (err) { // EXPECT: clean
    cb(err);
  }
}

export function loadPlan(path: string, done: Callback) {
  try {
    done(null, parsePlan(path));
  } catch (err) { // EXPECT: clean
    done(err);
  }
}

export function loadLater(path: string) {
  return new Promise((resolve, reject) => {
    try {
      resolve(parsePlan(path));
    } catch (e) { // EXPECT: clean
      reject(e);
    }
  });
}

export function decodeRow(raw: string) {
  try {
    return { ok: true, row: JSON.parse(raw) };
  } catch (err) { // EXPECT: clean
    const msg = err.message;
    return { ok: false, error: msg };
  }
}

export async function saveDraft(draft: Draft) {
  try {
    await drafts.save(draft);
  } catch (e) { // EXPECT: clean
    showFailureToast('Failed', Level.ERROR);
  }
}

// ---- the shapes below record nothing: each one stays a finding ----

export async function listOrders(request: Req, response: Res) {
  try {
    response.json(await orders.list(request.query));
  } catch (err) { // EXPECT: finding
    const message = String(err);
    response.status(500).json({ error: message });
  }
}

export async function listInvoices(req: Req, res: Res) {
  try {
    return res.json(await invoices.list(req.query));
  } catch (err) { // EXPECT: finding
    return res.status(500).json(readableMessage(err));
  }
}

export async function listCoupons(req: Req, res: Res) {
  try {
    return res.json(await coupons.list(req.query));
  } catch (err) { // EXPECT: finding
    res.status(400).json({ ...buildErrorPayload(Catalog.BAD_REQUEST) });
  }
}

export function parseQuantity(raw: string) {
  try {
    return Number.parseInt(raw, 10);
  } catch (err) { // EXPECT: finding
    return null;
  }
}

export function parseColour(raw: string) {
  try {
    return { ok: true, colour: toColour(raw) };
  } catch (err) { // EXPECT: finding
    return { ok: false, reason: 'INVALID' };
  }
}

export function suggestFor(id: string) {
  try {
    return { id, suggestion: rankFor(id) };
  } catch (err) { // EXPECT: finding
    return { id, suggestion: null };
  }
}

export function warmThumbnails() {
  try {
    thumbnails.warm();
  } catch (err) { // EXPECT: finding
    // best effort, nothing to do
  }
}

export function ingestRowBatch(rows: Row[]) {
  let failed = false;
  try {
    importer.run(rows);
  } catch (err) { // EXPECT: finding
    failed = true;
  }
  return !failed;
}

export function exportBatch(rows: Row[]) {
  try {
    exporter.run(rows);
  } catch (e) { // EXPECT: finding
    cleanup(e);
  }
}

export function renderChart(data: Point[]) {
  try {
    chart.draw(data);
  } catch (e) { // EXPECT: finding
    swallowError(e);
  }
}

export function renderLegend(data: Point[]) {
  try {
    legend.draw(data);
  } catch (e) { // EXPECT: finding
    ignoreFailures();
  }
}

export function renderAxis(data: Point[]) {
  try {
    axis.draw(data);
  } catch (e) { // EXPECT: finding
    clearFailures();
  }
}

export function renderGrid(data: Point[]) {
  try {
    grid.draw(data);
  } catch (e) { // EXPECT: finding
    resetErrorState();
  }
}

export function sendReceipt(req: Req, res: Res) {
  try {
    res.send(receipts.render(req.query));
  } catch (err) { // EXPECT: finding
    res.set('X-Error', err.message); res.status(500).end();
  }
}

export function refreshFeed() {
  try {
    feed.pull();
  } catch (err) { // EXPECT: finding
    setTimeout(() => reload(err), 1000);
  }
}

export function describeUpload(raw: string) {
  try {
    return describe(raw);
  } catch (exc) { // EXPECT: finding
    const detail = String(exc);
    return null;
  }
}
