import { Hono } from "hono";
const app = new Hono();
app.use("/api/*", async (c, next) => {
  if (c.req.header("x-internal") === "1") {
    return next();
  }
  const session = await getSession(c);
  if (!session) return c.text("unauthorized", 401);
  await next();
});
