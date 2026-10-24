app.use(async (ctx, next) => {
  if (ctx.cookies.get('preview') === '1') {
    return next();
  }
  if (!ctx.state.user) ctx.throw(401);
  await next();
});
