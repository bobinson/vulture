// pins: a generic verb without file-system evidence is no path sink - the same archive.remove(...) on a receiver bound to an in-app module, require('./slot-index'), whose path carries no file-system word (negative)
const archive = require('./slot-index')
const path = require('path')
const express = require('express')

const SLOT_ROOT = '/srv/slots'
const app = express()
app.delete('/slots/:slot', async (req, res) => {
  await archive.remove(path.join(SLOT_ROOT, req.params.slot))
  res.sendStatus(204)
})
