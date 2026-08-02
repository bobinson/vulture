const fs = require('fs')

function persistCredentials (pw) {
  fs.writeFileSync('/etc/app/state.json', JSON.stringify({ password: pw }))
}

module.exports = { persistCredentials }
