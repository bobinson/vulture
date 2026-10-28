// pins: an early exit one block above a nested read guards it only with a covering role - a deny-list of extensions (notePath.endsWith('.bak') || ...) returns before fs.readFile(notePath) nested in a later IF, so the read still reports (positive)
import fs from 'node:fs'
import path from 'node:path'
import express from 'express'

const NOTES_ROOT = '/srv/notes/'
const app = express()
app.use('/notes', (req, res, next) => {
  const notePath = path.join(NOTES_ROOT, req.path)
  if (notePath.endsWith('.bak') || notePath.endsWith('.swp')) {
    return res.status(403).end()
  }
  if (notePath.endsWith('.md')) {
    fs.readFile(notePath, 'utf8', (err, text) => (err ? next() : res.send(text)))
  }
})
