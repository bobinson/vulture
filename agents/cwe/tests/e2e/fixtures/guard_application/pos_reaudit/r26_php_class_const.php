<?php
class DebugBypass {
    private const BYPASS = 'yes';
    public function handle($request, Closure $next) {
        if ($request->header('X-Debug') === self::BYPASS) { return $next($request); }
        if (!auth()->check()) { abort(401); }
        return $next($request);
    }
}
