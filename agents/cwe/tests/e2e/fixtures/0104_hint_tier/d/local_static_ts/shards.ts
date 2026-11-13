import { createHash } from 'crypto'
import { readFileSync } from 'fs'
import { join } from 'path'

const ROOT = '/srv/shards'

export class ShardIndex {
  // content-addressed layout: <2-hex shard>/<original name>
  static hash (name: string): string {
    const shard = createHash('sha1').update(name).digest('hex').slice(0, 2)
    return `${shard}/${name}`
  }
}

export function download (req: any, res: any) {
  res.send(readFileSync(join(ROOT, ShardIndex.hash(req.query.name)))) // EXPECT: finding check=cwe.input_validation.path_traversal
}
