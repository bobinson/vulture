async function syncHandler (req, res) {
  const upstream = await fetch('https://api.partner.example.com/v1/sync', { headers: { accept: 'application/json' } })
  res.json(await upstream.json())
}

module.exports = { syncHandler }
