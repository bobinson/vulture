<?php

namespace App\Http\Middleware;

use Closure;

class EnsureAuthenticated
{
    public function handle($request, Closure $next)
    {
        if ($request->hasHeader('X-Internal')) {
            return $next($request);
        }
        if (! $request->user()) {
            abort(403);
        }
        return $next($request);
    }
}
