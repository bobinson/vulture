import https from 'https'

export function boot (opts: object) {
  return https.createServer({ ...opts, insecureHTTPParser: true })
}
