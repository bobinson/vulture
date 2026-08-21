const tls = require('tls')

function connect (host) {
  return tls.connect({ host, minVersion: 'TLSv1' })
}

module.exports = { connect }
