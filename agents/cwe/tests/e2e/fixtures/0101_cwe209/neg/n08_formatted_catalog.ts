try { p() } catch (err) {
  const quotaFault = formatQuotaError(err);
  // EXPECT-NEXT: clean  formatted catalog
  return res.status(quotaFault.code).json(catalogEnvelope(quotaFault));
}
