// pins: a generic verb imported from an in-app formatting module is no path sink - truncate from './text-format' shortens a request value (negative)
import express from 'express'
import { truncate } from './text-format'

const app = express()
app.get('/preview', (req, res) => {
  res.send(truncate(String(req.query.title), 40))
})
