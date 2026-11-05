module.exports = function handleFault(error, req, res, next) {
  const status = error.status || 500;
  // EXPECT-NEXT: finding  non-500 raw message in an error handler
  res.status(status).json({ error: status === 500 ? 'Unexpected server error.' : error.message });
};
