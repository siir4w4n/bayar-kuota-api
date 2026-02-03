<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Tymon\JWTAuth\Facades\JWTAuth;

class SessionMiddleware
{
    protected $sessionServiceUrl;

    public function __construct()
    {
        $this->sessionServiceUrl = env('SESSION_SERVICE_URL', 'http://127.0.0.1:8081');
    }

    public function handle(Request $request, Closure $next)
    {
        $sessionToken = $request->header('Session-Token');
        $jwtToken = $request->bearerToken();

        if (! $sessionToken) {
            return response()->json(['message' => 'Session token missing'], 401);
        }

        if (! $jwtToken) {
            return response()->json(['message' => 'JWT token missing'], 401);
        }

        // Verify session microservice
        $response = Http::withHeaders([
            'X-SESSION-SECRET' => env('JWT_SECRET_VERIFY'),
        ])->get(
            $this->sessionServiceUrl."/api/session/verify/{$sessionToken}"
        );

        $responseData = $response->json();

        if (! isset($responseData['session']) || ! is_array($responseData['session'])) {
            return response()->json(['message' => 'Invalid session data'], 401);
        }

        $sessionUserId = $responseData['session']['user_id'];

        // Decode JWT
        try {
            $userFromJwt = JWTAuth::setToken($jwtToken)->authenticate();
        } catch (\Exception $e) {
            return response()->json(['message' => 'Invalid JWT token'], 401);
        }

        // Pastikan user_id dari session sama dengan user_id dari JWT
        if ($userFromJwt->id != $sessionUserId) {
            return response()->json(['message' => 'JWT and session mismatch'], 401);
        }

        $request->merge(['session_user_id' => $sessionUserId]);

        return $next($request);
    }
}
