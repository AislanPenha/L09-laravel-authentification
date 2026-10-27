<?php

namespace App\Http\Controllers;

use App\Mail\NewUserConfirmation;
use App\Mail\ResetPassword;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Illuminate\Validation\Rules\Password;
use Illuminate\View\View;

class AuthController extends Controller
{
    public function login(): View
    {
        return view('auth.login');
    }

    public function authenticate(Request $request): RedirectResponse
    {
        // form validation
        $credentials = $request->validate(
            [
                'username' => 'required|min:3|max:30',
                'password' =>[
                    'required',
                    Password::min(8)->max(32)->mixedCase()->numbers(),

                ]
            ],
            [
                'username.required' => 'O usuário é obrigatório.',
                'username.min' => 'O usuário deve ter no mínimo :min caracteres.',
                'username.max' => 'O usuário deve ter no máximo :max caracteres.',

                'password.required' => 'A senha é obrigatória.',
                'password.min' => 'A senha deve ter no mínimo :min caracteres.',
                'password.max' => 'A senha deve ter no máximo :max caracteres.',
                // ./vendor/bin/sail artisan lang:publish | incluir a pasta lang
                // veja em validation.php dependendo do .env APP_LOCALE
            ]
        );

        // login tradicional do Laravel
        // tem que ser email e password
        // if(Auth::attempt($credentials)) {
        //     $request->session()->regenerate();
        //     return redirect()->route('home');
        // }

        // vereficar se o user existe
        $user = User::where('username', $credentials['username'])
                        ->where('active', true)
                        ->where(function($query){
                            $query->whereNull('blocked_until')
                                ->orWhere('blocked_until', '<=', Carbon::now());
                        })
                        ->whereNotNull('email_verified_at')
                        ->whereNull('deleted_at')
                        ->first();

        if (! $user) {
            return back()->withInput()->with([
                'invalid_login' => 'Login inválido (wheres).'
            ]);
        }

        // verificar se o password é válido
        if(!password_verify($credentials['password'], $user->password)) {
            return back()->withInput()->with([
                'invalid_login' => 'Login inválido (senha).'
            ]);
        }

        // atualizar o último login (last_login_at)
        $user->last_login_at = Carbon::now();
        $user->blocked_until = null;
        $user->save();


        // login propriamente dito
        $request->session()->regenerate();
        Auth::login($user);

        // redirecionar
        return redirect()->intended(route('home'));
    }

    public function logout(): RedirectResponse
    {
        Auth::logout();
        return redirect()->route('login');
    }

    public function register(): View
    {
        return view('auth.register');
    }

    public function store_user(Request $request): RedirectResponse|View
    {
        //form validation
        $request->validate(
            [
                'username' => 'required|min:3|max:30|unique:users,username',
                'email' => 'required|email|unique:users', // não precisa repetir se o campo é igual
                'password' =>[
                    'required',
                    Password::min(8)->max(32)->mixedCase()->numbers(),

                ],
                'new_password_confirmation' => 'required|same:password'
            ],
            [
                'username.required' => 'O usuário é obrigatório.',
                'username.min' => 'O usuário deve ter no mínimo :min caracteres.',
                'username.max' => 'O usuário deve ter no máximo :max caracteres.',
                'username.unique' => 'O usuário já está registrado.',

                'email.required' => 'O email é obrigatório.',
                'email.email' => 'O email deve ser um endereço de email válido.',
                'email.unique' => 'O email já está registrado.',

                'password.required' => 'A senha é obrigatória.',
                'password.min' => 'A senha deve ter no mínimo :min caracteres.',
                'password.max' => 'A senha deve ter no máximo :max caracteres.',

                'new_password_confirmation.required' => 'A confirmação da senha é obrigatória.',
                'new_password_confirmation.same' => 'A confirmação da senha deve ser igual a senha.',
            ]
        );

        // criar um novo usuário definindo um token de verificação do email
        $user = new User();
        $user->username = $request->username;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->token = Str::random(64);

        // gerar link
        $confirmation_link = route('new_user_confirmation', ['token' => $user->token]);

        // enviar email
        $result = Mail::to($user->email)->send(new NewUserConfirmation($user->username, $confirmation_link));

        // verificar se o email foi enviado com sucesso
        if(!$result) {
            return back()->withInput()->with([
                'server_error' => 'Ocorreu um erro ao enviar o email de confirmação.'
            ]);
        }
        
        // criar o usuário na base de dados
        $user->save();

        // apresentar a view de sucesso
        return view('auth.email_sent', ['email' => $user->email]);
    }

    public function new_user_confirmation(string $token): RedirectResponse|View
    {
        // verificar se o token é válido
        $user = User::where('token', $token)->first();

        if(!$user) {
            return redirect()->route('login');
        }

        // confirmar o registro do usuário
        $user->email_verified_at = Carbon::now();
        $user->token = null;
        $user->active = true;
        $user->save();

        // autenticação automática(login) do usuário confirmado
        Auth::login($user);
        
        // apresenta uma mensagem de sucesso
        return view('auth.new_user_confirmation');
    }

    public function forgot_password(): View
    {
        return view('auth.forgot_password');
    }

    public function send_reset_password_link(Request $request): RedirectResponse
    {
        // form validation
        $request->validate(
            [
                'email' => 'required|email',
            ],
            [
                'email.required' =>'O email é obrigatório.',
                'email.email' =>'O email deve ser um endereço de email válido.',
            ]
        );

        $generic_message = "Verifique a sua caixa de correio para prosseguir com a recuperação de senha.";

        // verificar se o email existe
        $user = User::where('email', $request->email)->first();
        if(!$user){
            return back()->with([
                'server_message' => $generic_message.'>>> email não existe <<<'
            ]);
        }

        // criar o link com token para enviar no email
        $user->token = Str::random(64);
        $token_link = route('reset_password', ['token' => $user->token]);

        // envio do email com link para recuperar a senha
        $result = Mail::to($user->email)->send(new ResetPassword($user->username, $token_link));

        // verifica se o email foi enviado
        if(!$result) {
            return back()->with([
                'server_message' => $generic_message.'>>> email não enviado <<<'
            ]);
        }

        // gaurda o token na base de dados
        $user->save();

        return back()->with([
                'server_message' => $generic_message.'>>> OK <<<'
        ]);
    }

    public function reset_password(string $token): View|RedirectResponse
    {
        // veririca se o token é válido
        $user = User::where('token', $token)->first();
        if(!$user) {
            return redirect()->route('login');
        }
        return view('auth.reset_password', ['token' => $token]);
    }

    public function reset_password_update(Request $request): RedirectResponse
    {
        // form validation
        $request->validate(
            [
                'token' => 'required',
                'new_password' =>[
                    'required',
                    Password::min(8)->max(32)->mixedCase()->numbers(),

                ],
                'new_password_confirmation' => 'required|same:new_password'
            ],
            [
                'new_password.required' => 'A nova senha é obrigatória.',
                'new_password.min' => 'A nova senha deve ter no mínimo :min caracteres.',
                'new_password.max' => 'A nova senha deve ter no máximo :max caracteres.',

                'new_password_confirmation.required' => 'A confirmação da senha é obrigatória.',
                'new_password_confirmation.same' => 'A confirmação da senha deve ser igual a nova senha.',
            ]
        );

        // verifica se o token é válido
        $user = User::where('token', $request->token)->first();
        if(!$user){
            return redirect()->route('login');
        }

        // atualizar a senha do user na base dados
        $user->password = bcrypt($request->new_password);
        $user->token = null;
        $user->save();

        return redirect()->route('login')->with([
            'success' => true
        ]);
    }

    public function delete_account(Request $request): RedirectResponse
    {
        // form validation
        $request->validate(
            [
                'delete_confirmation' => 'required|in:ELIMINAR'
            ],
            [
                'delete_confirmation.required' => 'A confirmação é obrigatória.',
                'delete_confirmation.in' => 'É obrigatório escrever a palavra \'ELIMINAR\'',
            ]
        );

        
        /** @var \App\Models\User $user */
        // soft delete
        $user = Auth::user();
        
        $user->delete();
    
        // hard delete
        // $user->forceDelete();

        // logout
        Auth::logout();

        return redirect()->route('login')->with(['account_deleted' => true]);
    }
}
