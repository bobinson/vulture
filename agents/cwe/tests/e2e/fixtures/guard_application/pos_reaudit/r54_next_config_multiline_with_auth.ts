import { withAuth } from 'next-auth/middleware'
export default withAuth(function middleware() {})

const matcher = [
  { source: '/admin/:path*', missing: [{ type: 'header', key: 'x-internal' }] },
]

export const config = {
  matcher,
  runtime: 'nodejs',
}
