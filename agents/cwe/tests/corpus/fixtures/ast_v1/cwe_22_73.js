// pins: a generic verb with file-system evidence stays a path sink - archive.remove(...) on a receiver bound to require('fs-extra') (a file-system word in its whole module path) removes a request-chosen slot (positive)
const archive = require('fs-extra')
const path = require('path')
const express = require('express')

const SLOT_ROOT = '/srv/slots'
const app = express()
app.delete('/slots/:slot', async (req, res) => {
  await archive.remove(path.join(SLOT_ROOT, req.params.slot))
  res.sendStatus(204)
})
