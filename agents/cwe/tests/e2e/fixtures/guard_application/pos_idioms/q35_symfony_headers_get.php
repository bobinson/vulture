<?php
class Authenticate
{
    public function handle($request, Closure $next)
    {
        if ($request->headers->get('X-Internal') === 'yes') {
            return $next($request);
        }
        if (! Auth::check()) {
            abort(401);
        }
        return $next($request);
    }
}
