// pins: a Buffer's copy() is no path sink - given.copy(padded) pads a request-derived signature for a constant-time compare, no file-system word in the receiver (negative)
const crypto = require('crypto')
const express = require('express')

const WEBHOOK_KEY = Buffer.from(process.env.WEBHOOK_KEY || '')
const app = express()
app.post('/hook', (req, res) => {
  const given = Buffer.from(req.get('x-signature') || '')
  const padded = Buffer.alloc(Math.max(given.length, WEBHOOK_KEY.length))
  given.copy(padded)
  res.sendStatus(crypto.timingSafeEqual(padded, WEBHOOK_KEY) ? 204 : 401)
})
