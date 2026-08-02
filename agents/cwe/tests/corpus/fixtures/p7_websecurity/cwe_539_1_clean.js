function remember(res, token) {
  res.cookie("remember_token", token, {
    maxAge: 3600000,
    httpOnly: true, secure: true, sameSite: "strict",
  });
}
