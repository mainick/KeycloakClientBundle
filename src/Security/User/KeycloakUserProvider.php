<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Security\User;

use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class KeycloakUserProvider implements UserProviderInterface
{
    public function __construct(
        private readonly LoggerInterface $keycloakClientLogger,
        private readonly IamClientInterface $iamClient
    ) {
    }

    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof KeycloakResourceOwner) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        $accessToken = $user->getAccessToken();
        if ($accessToken && $accessToken->hasExpired()) {
            $accessToken = $this->iamClient->refreshToken($accessToken);
        }

        return $this->loadUserByIdentifier($accessToken);
    }

    public function supportsClass(string $class): bool
    {
        return KeycloakResourceOwner::class === $class;
    }

    public function loadUserByIdentifier($identifier): UserInterface
    {
        if (!$identifier instanceof AccessTokenInterface) {
            throw new \LogicException('Could not load a KeycloakUser without an AccessToken.');
        }

        try {
            $resourceOwner = $this->iamClient->fetchUserFromToken($identifier);
        }
        catch (\UnexpectedValueException $e) {
            $this->keycloakClientLogger->warning($e->getMessage());
            $this->keycloakClientLogger->warning('User should have been disconnected from Keycloak server');

            throw new UserNotFoundException(sprintf('User with access token "%s" not found.', $identifier));
        }
        $this->keycloakClientLogger->info('KeycloakUserProvider::loadUserByIdentifier', [
            'resourceOwner' => $resourceOwner->toArray(),
        ]);

        return $resourceOwner;
    }
}
