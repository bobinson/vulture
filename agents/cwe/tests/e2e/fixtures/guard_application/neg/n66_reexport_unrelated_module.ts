export { formatAuthor as default } from './author'
export const config = { matcher: [{ source: '/a', missing: [{ type: 'header', key: 'x-skip' }] }] }
