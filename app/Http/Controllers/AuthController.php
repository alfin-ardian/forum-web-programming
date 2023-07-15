<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
// import the User model
use App\Models\User;

class AuthController extends Controller
{
    // Get all users
    public function index()
    {
        // Get all users
        $users = User::all();

        // Return response
        return response()->json(['users' => $users], 200);
    }

    // Register a new user
    public function register(Request $request)
    {
        // Validate request data
        $this->validate($request, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:8|confirmed',
        ]);

        // Create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        // Generate and attach an API token to the user
        $token = $user->createToken('api_token')->plainTextToken;

        // Return response
        return response()->json(['user' => $user, 'token' => $token], 201);
    }

    // Login and generate API token
    public function login(Request $request)
    {
        // Validate request data
        $this->validate($request, [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // Attempt to authenticate user
        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $user = Auth::user();
            $token = $user->createToken('api_token')->plainTextToken;
            return response()->json(['user' => $user, 'token' => $token], 200);
        }

        // Failed authentication
        throw ValidationException::withMessages(['email' => 'Invalid email or password.']);
    }

    // Logout and revoke API token
    public function logout(Request $request)
    {
        // Revoke the user's API token
        $request->user()->currentAccessToken()->delete();

        // Return response
        return response()->json(['message' => 'Logged out successfully.'], 200);
    }
}
