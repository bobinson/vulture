// held-out heldout_01 (CWE-22): an upload written to a path built from the session owner's id and a sniffed file type's extension
// HELD-OUT-TOKENS: fromBuffer
import fs from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import * as sessions from './sessions'

export function storeAvatarUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const upload = req.file
    const buffer = upload?.buffer
    if (buffer === undefined) {
      res.status(500)
      next(new Error('missing upload'))
      return
    }
    const sniffed = await fileType.fromBuffer(buffer)
    if (sniffed === undefined) {
      res.status(500)
      next(new Error('unknown type'))
      return
    }
    if (sniffed === null || !sniffed.mime.startsWith('image')) {
      res.status(415)
      next(new Error('not an image'))
      return
    }
    const owner = sessions.activeOwners.get(req.cookies.token)
    if (!owner) {
      next(new Error('no session'))
      return
    }

    const filePath = `store/avatars/${owner.data.id}.${sniffed.ext}`
    try {
      await fs.writeFile(filePath, buffer)
    } catch (err) {
      next(err)
    }
  }
}
