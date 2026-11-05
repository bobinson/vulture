function login(req, response, token) {
  response.cookie("sid", token, { // EXPECT: clean
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });
  response.end();
}

module.exports = login;
