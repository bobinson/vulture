function issueApiKey () {
  const apiKey = Math.random().toString(36).slice(2)
  return apiKey
}

module.exports = { issueApiKey }
