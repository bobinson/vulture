import { NextResponse } from 'next/server'
export function middleware(req) {
  const t = req.cookies.get('session')
  if (!t) return NextResponse.redirect(new URL('/login', req.url))
  return NextResponse.next()
}
const matcher = [{ source: '/a', missing: [{ type: 'header', key: 'x-skip' }] }]
export const config = { matcher }
