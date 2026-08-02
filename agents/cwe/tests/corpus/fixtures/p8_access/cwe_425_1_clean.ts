export function register (app: Express) {
  app.get('/rest/admin/application-configuration', security.isAuthorized(), serveConfiguration())
}
