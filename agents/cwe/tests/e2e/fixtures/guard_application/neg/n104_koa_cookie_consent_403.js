app.use(async (ctx, next) => {
  if (ctx.cookies.get('cookie_consent') === 'yes') {
    return next();
  }
  ctx.status = 403;
  ctx.body = 'Please accept cookies';
});
