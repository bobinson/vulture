const helmet = require('helmet')

function boot (app) {
  app.use(helmet({ frameguard: false }))
  return app
}
