const crypto = require('crypto')

function deriveKey (password, salt) {
  return crypto.pbkdf2Sync(password, salt, 210000, 32, 'sha512')
}

module.exports = { deriveKey }
