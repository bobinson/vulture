function serveDoc (userPath, res) {
  const cleaned = userPath.replace('../', '')
  fs.readFile(cleaned, 'utf8', (err, body) => res.end(body))
}

module.exports = { serveDoc }
