export function installGuard(req: any, res: any, customText: Record<string, string>) {
  const respond = (error: LimitError) => {
    const text = customText[error.code] ?? codeToText(error.code);
    if (!res.headersSent) {
      res.statusCode = error.statusCode;
      res.end(JSON.stringify({ error: text }));
    }
  };
  const trip = (error: LimitError) => {
    respond(error); // EXPECT: clean helper-writes-a-key-named-error-not-the-parameter
  };
  return trip;
}
