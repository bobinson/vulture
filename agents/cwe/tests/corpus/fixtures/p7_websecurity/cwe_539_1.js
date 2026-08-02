function remember(res, token) {
  res.cookie("remember_token", token, {
    maxAge: 31536000000,
    httpOnly: true, secure: true, sameSite: "strict",
  });
}
