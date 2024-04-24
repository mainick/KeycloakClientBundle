<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

enum KeycloakAuthorizationCodeEnum: string
{
    public const STATE_SESSION_KEY = 'mainick.oauth2state';
    public const LOGIN_REFERRER = 'mainick.loginReferrer';
    public const CODE_KEY = 'code';
    public const STATE_KEY = 'state';
}
