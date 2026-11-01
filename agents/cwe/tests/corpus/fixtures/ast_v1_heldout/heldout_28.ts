// held-out heldout_28 (CWE-22): readFile of a path resolved under a fixed root from the normalised request path, then prefix-checked
import path from 'node:path'
import fs from 'node:fs'
import express, { type Request, type Response, type NextFunction } from 'express'

export function mountDocs (app: express.Express) {
  app.use('/docs', (req: Request, res: Response, next: NextFunction) => {
    const filePath = path.resolve('docs', path.normalize(req.path).replace(/^[\\/]+/, ''))
    if (!filePath.startsWith(path.resolve('docs')) || filePath.endsWith('README.md')) {
      return res.status(403).end()
    }
    if (filePath.endsWith('.tf') || filePath.endsWith('.yml')) {
      fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return next()
        res.type('text/plain').send(data)
      })
    } else {
      express.static('docs')(req, res, next)
    }
  })
}
