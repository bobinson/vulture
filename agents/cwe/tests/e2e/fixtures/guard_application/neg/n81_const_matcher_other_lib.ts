import { verifyJwt } from './jwt';
const matcher = createRouteMatcher([{ path: '/api', has: [{ type: 'header', key: 'x-tenant' }] }]);
export function route(req) {
  if (!verifyJwt(req)) return new Response(null, { status: 401 });
  return matcher(req);
}
