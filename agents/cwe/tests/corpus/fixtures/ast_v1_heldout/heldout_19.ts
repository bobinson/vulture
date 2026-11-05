// held-out heldout_19 (CWE-22): readFile of a constant directory plus a name from readdir of that same directory
import { readFile, readdir } from 'node:fs/promises'
import { type Request, type Response, type NextFunction } from 'express'

export function listLocales () {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const baseStr = await readFile('assets/i18n/en.json', 'utf-8')
      const base = JSON.parse(baseStr)
      const localeFiles = await readdir('assets/i18n/')

      const results = localeFiles.map(async (fileName) => {
        const content = await readFile('assets/i18n/' + fileName, 'utf-8')
        const parsed = JSON.parse(content)
        const key = fileName.substring(0, fileName.indexOf('.'))
        return { key, ratio: coverageOf(parsed, base) }
      })
      res.json(await Promise.all(results))
    } catch (err) {
      next(err)
    }
  }
}
