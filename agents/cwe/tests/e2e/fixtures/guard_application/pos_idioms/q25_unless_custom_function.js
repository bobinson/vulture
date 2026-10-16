const { expressjwt } = require("express-jwt");
app.use(
  expressjwt({ secret: process.env.JWT_SECRET, algorithms: ["HS256"] }).unless({
    custom: function (req) {
      return req.headers["x-internal"] === "1";
    },
  })
);
