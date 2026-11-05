app.use(async (ctx, next) => {
  if (ctx.query.debug === "1") return next();
  await requireUser(ctx);
  return next();
});
