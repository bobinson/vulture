module.exports = function auth(req, res, next) {
  if (req.headers['stripe-signature']) {
    const event = stripe.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], whsec);
    req.stripeEvent = event;
    return next();
  }
  if (!req.session.user) {
    return res.status(401).end();
  }
  next();
};
