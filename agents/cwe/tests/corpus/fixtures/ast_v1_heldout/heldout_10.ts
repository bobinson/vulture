// held-out heldout_10 (CWE-22): a handler reading a constant template path whose file name begins with a user word
import { type Request, type Response, type NextFunction } from 'express'
import fs from 'node:fs/promises'

export function renderAccountCard () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userCard.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }
    res.locals.template = template
    next()
  }
}
