// pins: a generic verb on a storage object is no path sink - draftStorage.save(req.body.title, ...) with no file-system word in its receiver chain or the module it is bound from (negative)
import express from 'express'
import { createDraftStorage } from './draft-storage'

const draftStorage = createDraftStorage()
const app = express()
app.post('/drafts', (req, res) => {
  draftStorage.save(req.body.title, req.body.text)
  res.sendStatus(201)
})
