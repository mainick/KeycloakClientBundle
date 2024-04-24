<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Security\EntryPoint;

use Mainick\KeycloakClientBundle\DTO\KeycloakAuthorizationCodeEnum;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

final readonly class KeycloakAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    public function __construct(
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        if ($request->hasSession()) {
            $request->getSession()->set(KeycloakAuthorizationCodeEnum::LOGIN_REFERRER, $request->getUri());
        }

        return new RedirectResponse(
            $this->urlGenerator->generate('mainick_keycloak_security_auth_connect'),
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }
}
