const http = require('http')

function boot (handler) {
  return http.createServer({ insecureHTTPParser: true }, handler)
}
