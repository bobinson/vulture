import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export function sessionStoreDir (): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'session-'))
  return dir
}
