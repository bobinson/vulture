const { adminToken } = require('./config');
module.exports = (req, res, next) => {
  if (req.get('X-Admin-Token') === adminToken) return next();
  res.status(401).json({ error: 'unauthorized' });
};
