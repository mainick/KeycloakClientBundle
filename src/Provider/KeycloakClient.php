<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use League\OAuth2\Client\Token\AccessToken as AccessTokenLib;
use Mainick\KeycloakClientBundle\DTO\UserRepresentationDTO;
use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use Mainick\KeycloakClientBundle\Token\TokenDecoderFactory;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class KeycloakClient implements IamClientInterface
{
    private Keycloak $keycloakProvider;

    public function __construct(
        private readonly LoggerInterface $keycloakClientLogger,
        private readonly bool $verify_ssl,
        private readonly string $base_url,
        private readonly string $realm,
        private readonly string $client_id,
        private readonly string $client_secret = '',
        private readonly string $redirect_uri = '',
        private readonly string $encryption_algorithm = 'HS256',
        private readonly string $encryption_key = '',
        private readonly string $encryption_key_path = '',
        private readonly string $version = '',
    ) {
        $this->keycloakProvider = new Keycloak([
            'authServerUrl' => $this->base_url,
            'realm' => $this->realm,
            'clientId' => $this->client_id,
            'clientSecret' => $this->client_secret,
            'redirectUri' => $this->redirect_uri,
            'encryptionAlgorithm' => $this->encryption_algorithm,
        ]);

        if ('RS256' === $this->encryption_algorithm) {
            if ('' === $this->encryption_key && '' === $this->encryption_key_path) {
                throw new \RuntimeException('encryption_key is empty');
            }
            if ('' !== $this->encryption_key) {
                $this->keycloakProvider->setEncryptionKey($this->encryption_key);
            }
            if ('' !== $this->encryption_key_path) {
                $this->keycloakProvider->setEncryptionKeyPath($this->encryption_key_path);
            }
        }

        if ('' !== $this->version) {
            $this->keycloakProvider->setVersion($this->version);
        }

        $httpClient = new Client([
            'verify' => $this->verify_ssl,
        ]);
        $this->keycloakProvider->setHttpClient($httpClient);
    }

    public function setHttpClient(ClientInterface $httpClient): void
    {
        $this->keycloakProvider->setHttpClient($httpClient);
    }

    public function refreshToken(AccessTokenInterface $token): ?AccessTokenInterface
    {
        try {
            $token = $this->keycloakProvider->getAccessToken('refresh_token', [
                'refresh_token' => $token->getRefreshToken(),
            ]);
            $accessToken = new AccessToken();
            $accessToken->setToken($token->getToken())
                ->setExpires($token->getExpires())
                ->setRefreshToken($token->getRefreshToken())
                ->setValues($token->getValues());

            return $accessToken;
        }
        catch (\Exception $e) {
            $this->keycloakClientLogger->error('KeycloakClient::refreshToken', [
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    public function verifyToken(AccessTokenInterface $token): ?UserRepresentationDTO
    {
        try {
            $accessToken = new AccessTokenLib([
                'access_token' => $token->getToken(),
                'refresh_token' => $token->getRefreshToken(),
                'expires' => $token->getExpires(),
                'values' => $token->getValues(),
            ]);

            $decoder = TokenDecoderFactory::create($this->encryption_algorithm);
            $tokenDecoded = $decoder->decode($accessToken->getToken(), $this->encryption_key);
            $this->keycloakClientLogger->info('KeycloakClient::verifyToken', [
                'tokenDecoded' => $tokenDecoded,
            ]);

            $user = new KeycloakResourceOwner($tokenDecoded);
            $this->keycloakClientLogger->info('KeycloakClient::verifyToken', [
                'user' => $user->toArray(),
            ]);

            return UserRepresentationDTO::fromArray($user->toArray());
        }
        catch (\Exception $e) {
            $this->keycloakClientLogger->error('KeycloakClient::verifyToken', [
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    public function userInfo(AccessTokenInterface $token): ?UserRepresentationDTO
    {
        try {
            $this->verifyToken($token);
            $accessToken = new AccessTokenLib([
                'access_token' => $token->getToken(),
                'refresh_token' => $token->getRefreshToken(),
                'expires' => $token->getExpires(),
                'values' => $token->getValues(),
            ]);
            $resourceOwner = $this->keycloakProvider->getResourceOwner($accessToken);
            $user = new KeycloakResourceOwner($resourceOwner->toArray());
            $this->keycloakClientLogger->info('KeycloakClient::userInfo', [
                'user' => $user->toArray(),
            ]);

            return UserRepresentationDTO::fromArray($user->toArray());
        }
        catch (\Exception $e) {
            $this->keycloakClientLogger->error('KeycloakClient::userInfo', [
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    public function getState(): string
    {
        return $this->keycloakProvider->getState();
    }

    /**
     * @param array<string,string> $options
     */
    public function getAuthorizationUrl(array $options = []): string
    {
        return $this->keycloakProvider->getAuthorizationUrl($options);
    }

    /**
     * @param array<string,string> $options
     */
    public function logoutUrl(array $options = []): string
    {
        return $this->keycloakProvider->getLogoutUrl($options);
    }

    /**
     * @param array<string,string> $options
     */
    public function authorize(array $options, ?callable $redirectHandler = null): never
    {
        try {
            $this->keycloakProvider->authorize($options, $redirectHandler);
        }
        catch (\Exception $e) {
            $this->keycloakClientLogger->error('KeycloakClient::authorize', [
                'error' => $e->getMessage(),
            ]);
        }
        exit;
    }

    public function authenticate(string $username, string $password): ?AccessTokenInterface
    {
        try {
            $token = $this->keycloakProvider->getAccessToken('password', [
                'username' => $username,
                'password' => $password,
                'scope' => 'openid',
            ]);
            $accessToken = new AccessToken();
            $accessToken->setToken($token->getToken())
                ->setExpires($token->getExpires())
                ->setRefreshToken($token->getRefreshToken())
                ->setValues($token->getValues());

            $this->keycloakClientLogger->info('KeycloakClient::authenticate', [
                'token' => $accessToken->getToken(),
                'expires' => $accessToken->getExpires(),
                'refresh_token' => $accessToken->getRefreshToken(),
            ]);

            return $accessToken;
        }
        catch (\Exception $e) {
            $this->keycloakClientLogger->error('KeycloakClient::authenticate', [
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    public function authenticateByCode(string $code): ?AccessTokenInterface
    {
        try {
            $token = $this->keycloakProvider->getAccessToken('authorization_code', [
                'code' => $code,
            ]);
            $accessToken = new AccessToken();
            $accessToken->setToken($token->getToken())
                ->setExpires($token->getExpires())
                ->setRefreshToken($token->getRefreshToken())
                ->setValues($token->getValues());

            $this->keycloakClientLogger->info('KeycloakClient::authenticateByCode', [
                'token' => $accessToken->getToken(),
                'expires' => $accessToken->getExpires(),
                'refresh_token' => $accessToken->getRefreshToken(),
            ]);

            return $accessToken;
        }
        catch (\Exception $e) {
            $this->keycloakClientLogger->error('KeycloakClient::authenticateByCode', [
                'error' => $e->getMessage(),
            ]);

            return null;
        }
    }

    /**
     * @param array<string> $roles
     */
    public function hasAnyRole(AccessTokenInterface $token, array $roles): bool
    {
        $token_introspect = $this->verifyToken($token);
        $exists = array_intersect($roles, $token_introspect['roles']);

        return count($exists) > 0;
    }

    /**
     * @param array<string> $roles
     */
    public function hasAllRoles(AccessTokenInterface $token, array $roles): bool
    {
        $token_introspect = $this->verifyToken($token);
        $exists = array_intersect($roles, $token_introspect['roles']);

        return count($exists) === count($roles);
    }

    public function hasRole(AccessTokenInterface $token, string $role): bool
    {
        $token_introspect = $this->verifyToken($token);

        return in_array($role, $token_introspect['roles'], true);
    }

    /**
     * @param array<string> $scopes
     */
    public function hasAnyScope(AccessTokenInterface $token, array $scopes): bool
    {
        throw new \RuntimeException('Not implemented');
    }

    /**
     * @param array<string> $scopes
     */
    public function hasAllScopes(AccessTokenInterface $token, array $scopes): bool
    {
        throw new \RuntimeException('Not implemented');
    }

    public function hasScope(AccessTokenInterface $token, string $scope): bool
    {
        throw new \RuntimeException('Not implemented');
    }

    /**
     * @param array<string> $groups
     */
    public function hasAnyGroup(AccessTokenInterface $token, array $groups): bool
    {
        $token_introspect = $this->verifyToken($token);
        $exists = array_intersect($groups, $token_introspect['groups']);

        return count($exists) > 0;
    }

    /**
     * @param array<string> $groups
     */
    public function hasAllGroups(AccessTokenInterface $token, array $groups): bool
    {
        $token_introspect = $this->verifyToken($token);
        $exists = array_intersect($groups, $token_introspect['groups']);

        return count($exists) === count($groups);
    }

    public function hasGroup(AccessTokenInterface $token, string $group): bool
    {
        $token_introspect = $this->verifyToken($token);

        return in_array($group, $token_introspect['groups'], true);
    }
}
