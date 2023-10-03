<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Interface;

use Mainick\KeycloakClientBundle\DTO\ClientRepresentationDTO;
use Mainick\KeycloakClientBundle\DTO\GroupRepresentationDTO;
use Mainick\KeycloakClientBundle\DTO\UserRepresentationDTO;

interface IamAdminClientInterface
{
    public function getAdminAccessToken(): ?AccessTokenInterface;

    /**
     * @return array<int, ClientRepresentationDTO>
     */
    public function getClients(array $parameters): ?array;

    public function getClient(string $id): ?ClientRepresentationDTO;

    public function getClientSecret(string $id): ?string;

    /**
     * @return array<int, UserRepresentationDTO>
     */
    public function getUsers(array $parameters): ?array;

    public function getUser(string $id): UserRepresentationDTO;

    /**
     * @return array<int, GroupRepresentationDTO>
     */
    public function getGroups(array $parameters): ?array;

    public function getGroup(string $id): ?GroupRepresentationDTO;

    public function getRealmRoles(): ?array;

    public function getClientRoles(): ?array;

    public function getUserGroups(string $id): ?array;

    public function getUserRoleMappings(string $id): ?array;

    public function getUserClientRoleMappings(string $id): ?array;

    public function getUserConsents(string $id): ?array;

    public function getUserSessions(string $id): ?array;

    public function getUserOfflineSessions(string $id): ?array;

    public function getUserFederatedIdentities(string $id): ?array;

    public function getUserCredentials(string $id): ?array;

    public function getUserSocialLogins(string $id): ?array;

    public function getUserGroupsCount(string $id): ?array;

    public function getUserSessionsCount(string $id): ?array;

    public function getUserOfflineSessionsCount(string $id): ?array;

    public function getUserFederatedIdentitiesCount(string $id): ?array;

    public function getUserCredentialsCount(string $id): ?array;

    public function getUserSocialLoginsCount(string $id): ?array;

    public function getUserConsentsCount(string $id): ?array;

    public function getUserRoleMappingsCount(string $id): ?array;

    public function getUserClientRoleMappingsCount(string $id): ?array;

    public function getUserGroupsRealmRoles(string $id, string $groupId): ?array;

    public function getUserGroupsClientRoles(string $id, string $groupId): ?array;

    public function getUserGroupsRealmRolesCount(string $id, string $groupId): ?array;

    public function getUserGroupsClientRolesCount(string $id, string $groupId): ?array;

    public function getUserGroup(string $id, string $groupId): ?array;

    public function addUserToGroup(string $id, string $groupId): ?bool;

    public function removeUserFromGroup(string $id, string $groupId): ?bool;

    public function addUserToGroupRealmRoles(string $id, string $groupId, array $roles): ?bool;

    public function removeUserFromGroupRealmRoles(string $id, string $groupId, array $roles): ?bool;

    public function addUserToGroupClientRoles(string $id, string $groupId, array $roles): ?bool;
}
