const helmet = require('helmet')

function boot (app) {
  app.use(helmet({ frameguard: { action: 'deny' } }))
  return app
}
