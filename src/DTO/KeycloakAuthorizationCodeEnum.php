<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

enum KeycloakAuthorizationCodeEnum: string
{
    const STATE_SESSION_KEY = 'mainick.oauth2state';
    const LOGIN_REFERRER = 'mainick.loginReferrer';
    const CODE_KEY = 'code';
    const STATE_KEY = 'state';
}
