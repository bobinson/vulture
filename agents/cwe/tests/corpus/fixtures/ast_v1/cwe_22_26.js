// pins: an iteration callback's first parameter takes the receiver's origins (R-B) - req.body.names.forEach((n) => ...)
function handler(req) {
  req.body.names.forEach((n) => {
    fs.readFile("/srv/docs/" + n, () => {});
  });
}
