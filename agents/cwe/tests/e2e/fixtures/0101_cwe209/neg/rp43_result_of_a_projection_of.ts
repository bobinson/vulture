export function h(req: any, res: any) {
  try {
    charge();
  } catch (err) {
    const quotaFault = formatQuotaError(err);
    // EXPECT-NEXT: clean  result of a projection of the error
    res.status(400).json({ message: quotaFault.message });
  }
}
