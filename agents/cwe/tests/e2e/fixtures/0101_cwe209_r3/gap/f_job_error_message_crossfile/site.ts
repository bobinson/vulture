export async function jobStatus(req: any, res: any, next: any) {
  try {
    const jobs = jobService.getProjectJobs(req.params.id);
    const latestJob = jobs.length > 0 ? jobs[jobs.length - 1] : null;
    res.json({ success: true, data: { renderJob: latestJob ? { id: latestJob.id, errorMessage: latestJob.errorMessage } : null } }); // EXPECT: clean
  } catch (error) {
    next(error);
  }
}
