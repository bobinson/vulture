export { auth as middleware } from '@/auth'
export const config = { matcher: [{ source: '/admin/:path*', missing: [{ type: 'header', key: 'x-skip' }] }] }
