module.exports = function previewRenderer(req, res, next) {
  if (req.query.preview) return next();
  res.locals.theme = req.cookies.theme || "light";
  return next();
};
