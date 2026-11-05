const jobs = new Map();
export async function runExport(job) {
  try {
    await exporter.run(job.spec);
    job.state = 'done';
  } catch (err) {
    job.state = 'failed';
    job.error = err.stack;
  }
}
export function exportStatus(req, res) {
  const job = jobs.get(req.params.id);
  res.json({ state: job.state, error: job.error }); // EXPECT: finding tp
}
