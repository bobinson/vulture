import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export function sessionStoreDir (): string {
  const dir = path.join(os.tmpdir(), 'session-store')
  fs.mkdirSync(dir, { recursive: true })
  return dir
}
