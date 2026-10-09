const { expressjwt } = require("express-jwt");

app.use(
  expressjwt({ secret: process.env.JWT_KEY, algorithms: ["HS256"] }).unless({
    path: ["/login", "/healthz"],
  }),
);
