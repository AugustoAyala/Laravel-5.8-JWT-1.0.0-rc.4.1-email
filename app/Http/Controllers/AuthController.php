<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Validator, DB, Hash, Mail;
use Illuminate\Support\Facades\Password;
use Illuminate\Mail\Message;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $credentials = $request->only('name', 'email', 'password');
        
        $rules = [
            'name' => 'required|max:255',
            'email' => 'required|email|max:255|unique:users'
        ];
        $validator = Validator::make($credentials, $rules);
        if($validator->fails()) {
            return response()->json(['success'=> false, 'error'=> $validator->messages()]);
        }
        $name = $request->name;
        $email = $request->email;
        $password = $request->password;
        
        $user = User::create(['name' => $name, 'email' => $email, 'password' => Hash::make($password)]);
        $verification_code = str_random(30); 
        DB::table('user_verifications')->insert(['user_id'=>$user->id,'token'=>$verification_code]);
        $subject = "Por favor verificar su correo electrónico.";
        Mail::send('email.verify', ['name' => $name, 'verification_code' => $verification_code],
            function($mail) use ($email, $name, $subject){
                $mail->from(getenv('FROM_EMAIL_ADDRESS'), "Augusto Ayala");
                $mail->to($email, $name);
                $mail->subject($subject);
            });
        return response()->json(['success'=> true, 'message'=> 'Gracias por registrarte! Por favor revise su correo electronico para completar su registro.']);
    }
    public function verifyUser($verification_code)
    {
        $check = DB::table('user_verifications')->where('token',$verification_code)->first();
        if(!is_null($check)){
            $user = User::find($check->user_id);
            if($user->is_verified == 1){
                return response()->json([
                    'success'=> true,
                    'message'=> 'Cuenta ya verificada..'
                ]);
            }
            $user->update(['is_verified' => 1]);
            DB::table('user_verifications')->where('token',$verification_code)->delete();
            return response()->json([
                'success'=> true,
                'message'=> 'Has verificado correctamente tu direccion de correo electronico.'
            ]);
        }
        return response()->json(['success'=> false, 'error'=> "El codigo de verificacion no es valido."]);
    }
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        
        $rules = [
            'email' => 'required|email',
            'password' => 'required',
        ];
        $validator = Validator::make($credentials, $rules);
        if($validator->fails()) {
            return response()->json(['success'=> false, 'error'=> $validator->messages()], 401);
        }
        
        $credentials['is_verified'] = 1;
        
        try {
            
            if (! $token = JWTAuth::attempt($credentials)) {
                return response()->json(['success' => false, 'error' => 'No podemos encontrar una cuenta con estas credenciales. Asegurese de haber ingresado la informacion correcta y de haber verificado su direccion de correo electronico.'], 404);
            }
        } catch (JWTException $e) {
            
            return response()->json(['success' => false, 'error' => 'Error al iniciar sesion, por favor intente de nuevo.'], 500);
        }
        // all good so return the token
        return response()->json(['success' => true, 'data'=> [ 'token' => $token ]], 200);
    }
    
    public function logout(Request $request) {
        $this->validate($request, ['token' => 'required']);
        
        try {
            JWTAuth::invalidate($request->input('token'));
            return response()->json(['success' => true, 'message'=> "Has cerrado sesion satisfactoriamente."]);
        } catch (JWTException $e) {
          
            return response()->json(['success' => false, 'error' => 'Error al cerrar sesión, por favor intente de nuevo.'], 500);
        }
    }
    public function recover(Request $request)
    {
        $user = User::where('email', $request->email)->first();
        if (!$user) {
            $error_message = "Su direccion de correo electrónico no fue encontrada.";
            return response()->json(['success' => false, 'error' => ['email'=> $error_message]], 401);
        }
        try {
            Password::sendResetLink($request->only('email'), function (Message $message) {
                $message->subject('Your Password Reset Link');
            });
        } catch (\Exception $e) {
            
            $error_message = $e->getMessage();
            return response()->json(['success' => false, 'error' => $error_message], 401);
        }
        return response()->json([
            'success' => true, 'data'=> ['message'=> 'Se ha enviado un correo electronico de reinicio. Por favor revise su correo electronico.']
        ]);
    }
}
