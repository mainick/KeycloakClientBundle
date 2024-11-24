<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Security\EntryPoint;

use Mainick\KeycloakClientBundle\DTO\KeycloakAuthorizationCodeEnum;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

final readonly class KeycloakAuthenticationEntryPoint implements AuthenticationEntryPointInterface
{
    public function __construct(
        private UrlGeneratorInterface $urlGenerator,
        private ?LoggerInterface $keycloakClientLogger = null,
    ) {
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        // Handling AJAX requests
        if ($request->isXmlHttpRequest()) {
            return new JsonResponse(
                [
                    'code' => Response::HTTP_UNAUTHORIZED,
                    'message' => 'Authentication Required',
                    'login_url' => $this->urlGenerator->generate('mainick_keycloak_security_auth_connect'),
                ],
                Response::HTTP_UNAUTHORIZED
            );
        }

        if ($request->hasSession()) {
            $request->getSession()->set(KeycloakAuthorizationCodeEnum::LOGIN_REFERRER, $request->getUri());

            $request->getSession()->getBag('flashes')->add(
                'info',
                'Please log in to access this page',
            );
        }

        $this->keycloakClientLogger?->info('KeycloakAuthenticationEntryPoint::start', [
            'path' => $request->getPathInfo(),
            'error' => $authException?->getMessage(),
            'loginReferrer' => $request->getUri(),
        ]);

        return new RedirectResponse(
            $this->urlGenerator->generate('mainick_keycloak_security_auth_connect'),
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }
}
