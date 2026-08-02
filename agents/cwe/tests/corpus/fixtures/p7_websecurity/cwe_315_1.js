function login(req, res) {
  res.cookie("password", req.body.password, {
    httpOnly: true, secure: true, sameSite: "strict",
  });
}
