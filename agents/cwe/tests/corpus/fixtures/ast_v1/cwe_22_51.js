// pins: a file-system call other than readFile - fs.createReadStream(p) with p built from the request is a path sink
function handler(req, res) {
  const p = "/srv/docs/" + req.params.name;
  fs.createReadStream(p).pipe(res);
}
