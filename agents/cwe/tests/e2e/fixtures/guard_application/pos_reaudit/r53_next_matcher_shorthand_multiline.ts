export { auth as middleware } from '@/auth'

const matcher = [
  { source: '/admin/:path*', missing: [{ type: 'header', key: 'x-internal' }] },
]

export const config = {
  matcher,
}
