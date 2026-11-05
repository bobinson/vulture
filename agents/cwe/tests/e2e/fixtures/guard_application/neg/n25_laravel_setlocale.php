<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\App;

class SetLocale
{
    public function handle($request, Closure $next)
    {
        if ($request->header('X-Locale')) {
            App::setLocale($request->header('X-Locale'));
            return $next($request);
        }
        if (auth()->check()) {
            App::setLocale(auth()->user()->locale);
        }
        return $next($request);
    }
}
