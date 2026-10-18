// pins: a response file sender is a path sink - res.sendFile("/srv/docs/" + name) with name from the request
function handler(req, res) {
  const name = req.params.name;
  res.sendFile("/srv/docs/" + name);
}
