// Express session cookie set with no options object at all.
function login (req, res) {
  const token = issueToken(req.body.email)
  res.cookie('token', token)
  res.json({ authentication: { token } })
}
module.exports = login
