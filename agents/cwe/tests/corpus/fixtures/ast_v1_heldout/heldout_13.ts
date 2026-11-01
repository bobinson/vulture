// held-out heldout_13 (CWE-918): put() on an in-memory token map, keyed by a token signed over a row the request updated
// HELD-OUT-TOKENS: findByPk
import { type Request, type Response, type NextFunction } from 'express'

import * as sessions from './sessions'
import * as helpers from './helpers'
import { AccountModel } from './models'

export function renameAccount () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const owner = sessions.activeOwners.get(req.cookies.token)

    if (!owner) {
      next(new Error('no session'))
      return
    }

    try {
      const account = await AccountModel.findByPk(owner.data.id)
      if (!account) {
        next(new Error('account not found'))
        return
      }

      const saved = await account.update({ username: req.body.username })
      const withStatus = helpers.rowToJson(saved)
      const freshToken = sessions.sign(withStatus)
      sessions.activeOwners.put(freshToken, withStatus)
      res.cookie('token', freshToken)
    } catch (error) {
      next(error)
    }
  }
}
