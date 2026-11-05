<?php
class Cron {
    public function handle($request, Closure $next) {
        if ($request->header('X-Cron-Key') === config('app.cron_key')) {
            return $next($request);
        }
        abort(403);
    }
}
