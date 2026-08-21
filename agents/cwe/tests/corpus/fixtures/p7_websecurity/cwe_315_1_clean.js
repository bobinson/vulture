function login(req, res) {
  res.cookie("password_changed_at", req.body.changedAt, {
    httpOnly: true, secure: true, sameSite: "strict",
  });
}
