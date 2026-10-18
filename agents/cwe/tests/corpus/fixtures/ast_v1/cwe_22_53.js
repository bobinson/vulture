// pins: a dynamic module load is a path sink - require("./plugins/" + req.query.name)
function handler(req) {
  return require("./plugins/" + req.query.name);
}
