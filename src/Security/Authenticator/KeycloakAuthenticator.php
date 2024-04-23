<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Security\Authenticator;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Mainick\KeycloakClientBundle\DTO\KeycloakAuthorizationCodeEnum;
use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Mainick\KeycloakClientBundle\Security\User\KeycloakUserProvider;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class KeycloakAuthenticator extends AbstractAuthenticator implements InteractiveAuthenticatorInterface
{
    public function __construct(
        private readonly LoggerInterface $keycloakClientLogger,
        private readonly IamClientInterface $iamClient,
        private readonly KeycloakUserProvider $userProvider
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return 'mainick_keycloak_security_auth_connect_check' === $request->attributes->get('_route');
    }

    public function authenticate(Request $request): Passport
    {
        $queryState = $request->query->get(KeycloakAuthorizationCodeEnum::STATE_KEY);
        $sessionState = $request->getSession()->get(KeycloakAuthorizationCodeEnum::STATE_SESSION_KEY);
        if (null === $queryState || $queryState !== $sessionState) {
            throw new AuthenticationException(sprintf('query state (%s) is not the same as session state (%s)', $queryState ?? 'NULL', $sessionState ?? 'NULL'));
        }

        $queryCode = $request->query->get(KeycloakAuthorizationCodeEnum::CODE_KEY);
        if (null === $queryCode) {
            throw new AuthenticationException('Authentication failed! Did you authorize our app?');
        }

        try {
            $accessToken = $this->iamClient->authenticateCodeGrant($queryCode);
        }
        catch (IdentityProviderException $e) {
            throw new AuthenticationException(sprintf('Error authenticating code grant (%s)', $e->getMessage()), previous: $e);
        }
        catch (\Exception $e) {
            throw new AuthenticationException(sprintf('Bad status code returned by openID server (%s)', $e->getStatusCode()), previous: $e);
        }

        if (!$accessToken || !$accessToken->getToken()) {
            $this->keycloakClientLogger->error('KeycloakAuthenticator::authenticate', [
                'error' => 'No access token provided',
            ]);
            throw new CustomUserMessageAuthenticationException('No access token provided');
        }

        if (!$accessToken->getRefreshToken()) {
            $this->keycloakClientLogger->error('Authenticator::authenticate', [
                'error' => 'Refresh token not found',
            ]);
            throw new CustomUserMessageAuthenticationException('Refresh token not found');
        }

        return new SelfValidatingPassport(new UserBadge($accessToken->getToken(), fn () => $this->userProvider->loadUserByIdentifier($accessToken)));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->getBag('flashes')->add(
            'error',
            'An authentication error occured',
        );

        // $message = strtr($exception->getMessageKey(), $exception->getMessageData());
        return new Response('Authentication failed', Response::HTTP_FORBIDDEN);
    }

    public function isInteractive(): bool
    {
        return true;
    }
}
