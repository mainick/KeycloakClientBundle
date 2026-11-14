<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Security\Authenticator;

use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use Mainick\KeycloakClientBundle\Token\RolesSourceEnum;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Stateless authenticator for APIs: reads the `Authorization: Bearer` header and verifies the
 * access token locally (signature, expiration, issuer) with {@see IamClientInterface::verifyToken()},
 * without calling Keycloak on each request.
 */
class KeycloakBearerAuthenticator extends AbstractAuthenticator
{
    private const PREFIX = 'Bearer ';

    private readonly RolesSourceEnum $rolesSource;

    /**
     * @param string                 $rolesSource    a {@see RolesSourceEnum} value: `all` or `authorized_party`
     * @param string[]               $allowedClients clients (`azp`) accepted; empty means any client of the realm
     * @param array<string,string[]> $clientRoles    extra roles granted, with `authorized_party`, according to the client that requested the token
     */
    public function __construct(
        private readonly LoggerInterface $keycloakClientLogger,
        private readonly IamClientInterface $iamClient,
        RolesSourceEnum|string $rolesSource = RolesSourceEnum::ALL,
        private readonly array $allowedClients = [],
        private readonly array $clientRoles = [],
    ) {
        $this->rolesSource = $rolesSource instanceof RolesSourceEnum ? $rolesSource : RolesSourceEnum::from($rolesSource);
    }

    public function supports(Request $request): ?bool
    {
        return str_starts_with((string) $request->headers->get('Authorization', ''), self::PREFIX);
    }

    public function authenticate(Request $request): Passport
    {
        $jwt = trim(substr((string) $request->headers->get('Authorization', ''), strlen(self::PREFIX)));
        if ('' === $jwt) {
            throw new CustomUserMessageAuthenticationException('Token not found');
        }

        $accessToken = new AccessToken();
        $accessToken->setToken($jwt);
        $accessToken->setRefreshToken('');
        $accessToken->setExpires(time());
        $accessToken->setValues([]);

        $user = $this->iamClient->verifyToken($accessToken);
        if (null === $user || null === $user->claims) {
            throw new CustomUserMessageAuthenticationException('Token not valid');
        }

        if ([] !== $this->allowedClients && !in_array($user->authorizedParty, $this->allowedClients, true)) {
            $this->keycloakClientLogger->warning('KeycloakBearerAuthenticator::authenticate', [
                'error' => 'Client not allowed',
                'azp' => $user->authorizedParty,
            ]);
            throw new CustomUserMessageAuthenticationException('Client not allowed');
        }

        $resourceOwner = new KeycloakResourceOwner($user->claims, $accessToken, $this->rolesSource, $this->clientRoles);

        return new SelfValidatingPassport(new UserBadge($user->id, static fn (): KeycloakResourceOwner => $resourceOwner));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return new JsonResponse(
            ['message' => $exception->getMessage()],
            Response::HTTP_UNAUTHORIZED,
        );
    }
}
