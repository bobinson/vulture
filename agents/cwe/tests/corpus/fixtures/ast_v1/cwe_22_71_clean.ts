// pins: an early exit dominates the rest of its function - a containment test (!notePath.startsWith(NOTES_ROOT) || ...) returns one block above fs.readFile(notePath) nested in a later IF, so the read declines guarded:path_contain (negative)
import fs from 'node:fs'
import path from 'node:path'
import express from 'express'

const NOTES_ROOT = '/srv/notes/'
const app = express()
app.use('/notes', (req, res, next) => {
  const notePath = path.join(NOTES_ROOT, req.path)
  if (!notePath.startsWith(NOTES_ROOT) || notePath.endsWith('.swp')) {
    return res.status(403).end()
  }
  if (notePath.endsWith('.md')) {
    fs.readFile(notePath, 'utf8', (err, text) => (err ? next() : res.send(text)))
  }
})
