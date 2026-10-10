module.exports = function auth(req, res, next) {
  // Shopify webhooks are authenticated by their HMAC signature.

  if (req.get('X-Shopify-Hmac-Sha256') && isValidShopifyRequest(req)) {
    return next();
  }
  if (!req.session.user) {
    return res.status(401).end();
  }
  next();
};
