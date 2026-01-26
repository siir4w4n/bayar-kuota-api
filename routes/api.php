<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\Controller;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

Route::get('/', [Controller::class, 'index']);

// Public routes
Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

// Protected routes pakai session middleware (hybrid: JWT + session microservice)
Route::middleware(['session'])->group(function () {

    // Ambil profile user (session_user_id sudah diattach oleh middleware)
    Route::get('/profile', [AuthController::class, 'profile']);

    // Logout user
    Route::post('/logout', [AuthController::class, 'logout']);
});
