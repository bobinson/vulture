function serveDoc (userPath, res) {
  const rel = path.relative(ROOT, path.resolve(ROOT, userPath))
  fs.readFile(rel, 'utf8', (err, body) => res.end(body))
}

module.exports = { serveDoc }
