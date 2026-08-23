// Clean twin of cwe_1275_1: SameSite=Strict.
function login (req, res) {
  const token = issueToken(req.body.email)
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'strict' })
  res.json({ authentication: { token } })
}
module.exports = login
