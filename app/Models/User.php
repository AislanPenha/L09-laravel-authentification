<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Attributes\Visible;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Foundation\Auth\User as AuthUser;

// #[Visible(['last_login_at'])]
#[Hidden(['password', 'token'])]
class User extends AuthUser
{
    use SoftDeletes;
    // attributes that are hidden for serialization
    // protected $hidden = [
    //     'password',
    //     'token'
    // ];
}
