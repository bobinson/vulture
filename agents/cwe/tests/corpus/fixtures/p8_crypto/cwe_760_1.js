const crypto = require('crypto')

function deriveKey (password) {
  return crypto.pbkdf2Sync(password, 'saltysalt', 1003, 16, 'sha1')
}

module.exports = { deriveKey }
