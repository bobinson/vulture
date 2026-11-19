function purge(ssh, req) {
  ssh.exec("DELETE FROM t WHERE id = " + req.query.id); // EXPECT: finding
}
module.exports = { purge };
