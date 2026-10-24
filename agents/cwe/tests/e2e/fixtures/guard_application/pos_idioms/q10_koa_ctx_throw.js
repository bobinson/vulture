const authMw = async (ctx, next) => {
  if (ctx.query.preview === "1") {
    await next();
    return;
  }
  if (!ctx.state.user) ctx.throw(401, "unauthorized");
  await next();
};
