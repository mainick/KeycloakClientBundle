<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Interface;

use Mainick\KeycloakClientBundle\DTO\UserRepresentationDTO;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;

interface IamClientInterface
{
    public function refreshToken(AccessTokenInterface $token): ?AccessTokenInterface;

    public function verifyToken(AccessTokenInterface $token): ?UserRepresentationDTO;

    public function userInfo(AccessTokenInterface $token): ?UserRepresentationDTO;

    public function userInfoRaw(AccessTokenInterface $token): ?array;

    public function fetchUserFromToken(AccessTokenInterface $token): ?KeycloakResourceOwner;

    /**
     * @param array<string,string> $options
     */
    public function getAuthorizationUrl(array $options = []): string;

    /**
     * @param array<string,string> $options
     */
    public function logoutUrl(array $options = []): string;

    /**
     * @param array<string,string> $options
     */
    public function authorize(array $options, ?callable $redirectHandler = null): never;

    public function authenticate(string $username, string $password): ?AccessTokenInterface;

    public function getState(): string;

    public function authenticateCodeGrant(string $code): ?AccessTokenInterface;

    /**
     * @param array<string> $roles
     */
    public function hasAnyRole(AccessTokenInterface $token, array $roles): bool;

    /**
     * @param array<string> $roles
     */
    public function hasAllRoles(AccessTokenInterface $token, array $roles): bool;

    public function hasRole(AccessTokenInterface $token, string $role): bool;

    /**
     * @param array<string> $scopes
     */
    public function hasAnyScope(AccessTokenInterface $token, array $scopes): bool;

    /**
     * @param array<string> $scopes
     */
    public function hasAllScopes(AccessTokenInterface $token, array $scopes): bool;

    public function hasScope(AccessTokenInterface $token, string $scope): bool;

    /**
     * @param array<string> $groups
     */
    public function hasAnyGroup(AccessTokenInterface $token, array $groups): bool;

    /**
     * @param array<string> $groups
     */
    public function hasAllGroups(AccessTokenInterface $token, array $groups): bool;

    public function hasGroup(AccessTokenInterface $token, string $group): bool;
}
