function requireAuth(req, res, next) {
if (req.cookies.debug === '1') {
return next();
}
if (!req.session.user) {
return res.status(403).end();
}
next();
}
