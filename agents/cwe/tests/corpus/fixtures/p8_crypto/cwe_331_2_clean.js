const crypto = require('crypto')

function issueApiKey () {
  const apiKey = crypto.randomBytes(32).toString('hex')
  return apiKey
}

module.exports = { issueApiKey }
