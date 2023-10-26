<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    // jwt-auth secret [1ds92s3xufI6pD23TXZmjmYllJNkCwrWTbny73xBdE8EE3ChL0BAuaGBrydDazvh]
    public function __construct()
    {
        $this->middleware('auth:api', ['except' =>['login']]);
    }
    public function login()
    {
        $credentials=request([
            'username','password'
        ]);
        if(!$token=auth()->attempt($credentials)){
            return response()->json([
                'message'=>'unauthorized',
            ], 401);
        }else{
            return response()->json([
                'access_token'=>$token,
                'token_type'=>'Bearer',
                'expires_in'=>auth()->factory()->getTTL(),
            ]);
        }
    }
    public function me()
    {
        return response()->json([
            'user'=> auth()->user()
        ]);
    }
    public function logout()
    {
        if(auth()->check()){
            auth()->logout();
            return response()->json([
                'message' => 'logout successful',
            ]);
        }else{
            return response()->json([
                'message' => 'terjadi kesalahan',
            ]);
        }
    }
    public function rpw(Request $request)
    {
        $user=auth()->user();
        $validator = Validator::make($request->all(), [
            'old_password' => 'required',
            'new_password' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 403);
        }
        if(Hash::check($request->old_password, $user->password)){

            $user->update([
                'password' => bcrypt($request->new_password)
            ]);
            auth()->logout();
            return response()->json([
                'message' => 'Successfully updated'
            ], 200);
        }
        if($request->old_password != $user->password){
            return response()->json([
                'message' => 'Old password didnt match',
            ], 422 );
        }

    }
}
