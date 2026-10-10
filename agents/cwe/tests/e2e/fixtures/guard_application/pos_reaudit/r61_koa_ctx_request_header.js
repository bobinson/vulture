async function auth(ctx, next) {
  if (ctx.request.headers['x-internal'] === 'true') {
    return next();
  }
  ctx.throw(401);
}
