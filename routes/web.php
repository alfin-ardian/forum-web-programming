<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will
| be assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});
Route::post('/register', 'AuthController@register');
Route::post('/login', 'AuthController@login');
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', 'AuthController@logout');
    // other protected routes...
});
