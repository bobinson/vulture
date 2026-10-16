function abVariant(req, res, next) {
  if (req.query.variant === 'b') {
    res.locals.variant = 'b';
    return next();
  }
  res.locals.variant = bucketFor(currentUser(req));
  next();
}
module.exports = abVariant;
