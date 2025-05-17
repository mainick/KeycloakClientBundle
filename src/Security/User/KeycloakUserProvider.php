<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Security\User;

use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
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
        if (!$accessToken) {
            $this->keycloakClientLogger->error('KeycloakUserProvider::refreshUser', [
                'message' => 'User does not have an access token.',
                'user_id' => $user->getUserIdentifier(),
            ]);
            throw new AuthenticationException('No valid access token available. Please login again.');
        }

        try {
            if ($accessToken->hasExpired()) {
                $accessToken = $this->iamClient->refreshToken($accessToken);
                if (!$accessToken) {
                    throw new AuthenticationException('Failed to refresh user session. Please login again.');
                }
            }

            return $this->loadUserByIdentifier($accessToken);
        }
        catch (\Exception $e) {
            $this->keycloakClientLogger->error('KeycloakUserProvider::refreshUser', [
                'error' => $e->getMessage(),
                'message' => 'Failed to refresh user access token',
                'user_id' => $user->getUserIdentifier(),
            ]);

            throw new AuthenticationException('Failed to refresh user session. Please login again.');
        }
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
            if (!$resourceOwner) {
                $this->keycloakClientLogger->info('KeycloakUserProvider::loadUserByIdentifier', [
                    'message' => 'User not found',
                    'token' => $identifier->getToken(),
                ]);
                throw new UserNotFoundException('User not found or invalid token.');
            }

            $this->keycloakClientLogger->info('KeycloakUserProvider::loadUserByIdentifier', [
                'resourceOwner' => $resourceOwner->toArray(),
            ]);

            return $resourceOwner;
        }
        catch (\UnexpectedValueException $e) {
            $this->keycloakClientLogger->warning('KeycloakUserProvider::loadUserByIdentifier', [
                'error' => $e->getMessage(),
                'message' => 'User should have been disconnected from Keycloak server',
                'token' => $identifier->getToken(),
            ]);

            throw new UserNotFoundException('Failed to load user from token.');
        }
    }
}
