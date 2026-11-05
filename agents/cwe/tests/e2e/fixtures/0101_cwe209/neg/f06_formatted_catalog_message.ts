try { p() } catch (err) {
  const quotaFault = formatQuotaError(err);
  // EXPECT-NEXT: clean  formatted catalog message
  return res.status(quotaFault.code).json({ message: quotaFault.message });
}
