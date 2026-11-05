export function h(req, res) {
  const errorPage = renderTemplate('404.html', { path: req.path })
  // EXPECT-NEXT: finding  known-gap errorPage toString
  res.status(404).send(errorPage.toString())
}
