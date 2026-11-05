function login(req, response, token) {
  response.cookie("sid", token, { // EXPECT: finding
    maxAge: 3600,
    path: "/",
  });
  response.end();
}

module.exports = login;
