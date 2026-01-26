<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SchedulerMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle($request, Closure $next)
    {
        $token = $request->header('AppToken');

        if (!$token || $token !== env('JWT_SECRET')) {
            return response()->json([
                'message' => 'Invalid App Token'
            ], 403);
        }

        return $next($request);
    }

}
