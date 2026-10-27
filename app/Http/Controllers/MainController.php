<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rules\Password;
use Illuminate\View\View;

class MainController extends Controller
{
    public function home(): View
    {
        return view('home');
    }

    public function profile(): View
    {
        return view('auth.profile');
    }

    public function change_password(Request $request)
    {
        // form validation
        $request->validate(
            [
                'current_password' =>[
                    'required',
                    Password::min(8)->max(32)->mixedCase()->numbers(),

                ],
                'new_password' =>[
                    'required',
                    'different:current_password',
                    Password::min(8)->max(32)->mixedCase()->numbers(),

                ],
                'new_password_confirmation' => 'required|same:new_password'
            ],
            [
                'current_password.required' => 'A senha atual é obrigatória.',
                'current_password.min' => 'A senha atual deve ter no mínimo :min caracteres.',
                'current_password.max' => 'A senha atual deve ter no máximo :max caracteres.',

                'new_password.required' => 'A nova senha atual é obrigatória.',
                'new_password.different' => 'A nova senha deve ser diferente da senha atual.',
                'new_password.min' => 'A nova senha atual deve ter no mínimo :min caracteres.',
                'new_password.max' => 'A nova senha atual deve ter no máximo :max caracteres.',

                'new_password_confirmation.required' => 'A confirmação da senha é obrigatória.',
                'new_password_confirmation.same' => 'A confirmação da senha deve ser igual a senha.',
            ]
        );

        // verificar se a password atual(current_password) está correta
        if(!password_verify($request->current_password, Auth::user()->password)) {
            return back()->with([
                'server_error' => 'A senha atual não está correta'
            ]);
        }

        // atualizar a senha na base de dados
        $user = Auth::user();
        $user->password = bcrypt($request->new_password);
        /** @var \App\Models\User $user */ // ajeita o vscode
        $user->save();

        // atualizar a password na sessão
        Auth::user()->password = bcrypt($request->new_password);

        // apresenta uma emsangem de sucesso
        return redirect()->route('profile')->with([
            'success' => 'A senha foi atualizada com sucesso'
        ]);
    }

}
