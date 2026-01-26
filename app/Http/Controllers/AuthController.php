<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    protected $sessionServiceUrl;

    public function __construct()
    {
        $this->sessionServiceUrl = env('SESSION_SERVICE_URL', 'http://127.0.0.1:8081');
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:6|confirmed',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $jwtToken = JWTAuth::fromUser($user);

        return response()->json([
            'status' => 'success',
            'user' => $user,
            'access_token' => $jwtToken,
        ], 201);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $credentials['email'])->first();

        if (! $user || ! Hash::check($credentials['password'], $user->password)) {
            return response()->json(['error' => 'Invalid email or password'], 401);
        }

        $jwtToken = JWTAuth::fromUser($user);
        $payload = JWTAuth::setToken($jwtToken)->getPayload();
        $expireAt = $payload->get('exp');

        $sessionResp = Http::withHeaders($this->sessionHeaders())
            ->post($this->sessionServiceUrl.'/api/session/create', [
                'user_id' => $user->id,
                'expire_at' => $expireAt,
            ]);

        if ($sessionResp->failed()) {
            return response()->json(['error' => 'Failed to generate session'], 500);
        }

        $sessionData = $sessionResp->json();

        return response()->json([
            'access_token' => $jwtToken,
            'session_id' => $sessionData['session_id'],
            'expires_at' => $expireAt,
        ]);

    }

    public function logout(Request $request)
    {
        $sessionToken = $request->header('Session-Token');

        if ($sessionToken) {
            Http::withHeaders($this->sessionHeaders())
                ->delete($this->sessionServiceUrl."/api/session/delete/{$sessionToken}");

        }

        JWTAuth::invalidate(JWTAuth::getToken());

        return response()->json([
            'status' => 'success',
            'message' => 'Logged out successfully',
        ]);
    }

    public function profile(Request $request)
    {
        $user = User::find($request->get('session_user_id'));

        if (! $user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        return response()->json($user);
    }

    protected function sessionHeaders()
    {
        return [
            'X-SESSION-SECRET' => env('JWT_SECRET_VERIFY'),
            'Accept' => 'application/json',
        ];
    }
}
