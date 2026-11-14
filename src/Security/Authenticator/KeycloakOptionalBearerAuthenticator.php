<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Security\Authenticator;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Same verification as {@see KeycloakBearerAuthenticator}, but an invalid token does not block the
 * request: it continues as anonymous. Useful for public routes that offer more to authenticated users.
 */
class KeycloakOptionalBearerAuthenticator extends KeycloakBearerAuthenticator
{
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return null;
    }
}
