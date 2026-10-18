// held-out heldout_22 (CWE-918): a fetch of a URL taken from the request body, inside a branch taken for a signed-in user
import { type Request, type Response, type NextFunction } from 'express'

import * as sessions from './sessions'

export function avatarFromLink () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*probe\/marker(.)*/) !== null) req.app.locals.sawProbe = true
      const owner = sessions.activeOwners.get(req.cookies.token)
      if (owner) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('link returned a non-OK status code or an empty body')
          }
          await saveAvatar(owner.data.id, await response.arrayBuffer())
        } catch (error) {
          next(error)
          return
        }
      }
    }
    res.location('/profile')
    res.redirect('/profile')
  }
}
