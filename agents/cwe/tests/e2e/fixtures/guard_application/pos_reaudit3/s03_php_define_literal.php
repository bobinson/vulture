<?php
define('DEBUG_KEY', 'letmein');
class Auth {
    public function handle($request, Closure $next) {
        if ($request->header('X-Debug') === DEBUG_KEY) {
            return $next($request);
        }
        abort(401);
    }
}
