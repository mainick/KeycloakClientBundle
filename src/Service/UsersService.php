<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserSessionCollection;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UPConfig;
use Mainick\KeycloakClientBundle\Representation\UserProfileMetadata;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserSessionRepresentation;

final class UsersService extends Service
{
    /**
     * @return UserCollection<UserRepresentation>|null
     */
    public function all(string $realm, ?Criteria $criteria = null): ?UserCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users', UserCollection::class, $criteria);
    }

    public function get(string $realm, string $userId): ?UserRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId, UserRepresentation::class);
    }

    public function count(string $realm, ?Criteria $criteria = null): int
    {
        $count = $this->executeQuery('admin/realms/'.$realm.'/users/count', 'array', $criteria);
        if (null === $count) {
            return 0;
        }

        return (int) $count;
    }

    public function create(string $realm, UserRepresentation $user): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/users', $user);
    }

    public function update(string $realm, string $userId, UserRepresentation $user): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/users/'.$userId, $user);
    }

    public function delete(string $realm, string $userId): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/users/'.$userId);
    }

    /**
     * @return UserSessionCollection<UserSessionRepresentation>|null
     */
    public function sessions(string $realm, string $userId): ?UserSessionCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/sessions', UserSessionCollection::class);
    }

    /**
     * @return UserSessionCollection<UserSessionRepresentation>|null
     */
    public function offlineSessions(string $realm, string $userId, string $clientId): ?UserSessionCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/offline-sessions/'.$clientId, UserSessionCollection::class);
    }

    /**
     * @return GroupCollection<GroupRepresentation>|null
     */
    public function groups(string $realm, string $userId): ?GroupCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/groups', GroupCollection::class);
    }

    public function groupsCount(string $realm, string $userId): int
    {
        $count = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/groups/count', 'array');
        if (null === $count) {
            return 0;
        }

        return (int) $count;
    }

    public function joinGroup(string $realm, string $userId, string $groupId): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/users/'.$userId.'/groups/'.$groupId);
    }

    public function leaveGroup(string $realm, string $userId, string $groupId): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/users/'.$userId.'/groups/'.$groupId);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function realmRoles(string $realm, string $userId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm', RoleCollection::class);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function availableRealmRoles(string $realm, string $userId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm/available', RoleCollection::class);
    }

    public function addRealmRole(string $realm, string $userId, RoleRepresentation $role): bool
    {
        $roles = new RoleCollection();
        $roles->add($role);
        return $this->executeCommand(
            HttpMethodEnum::POST,
            'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm',
            $roles
        );
    }

    public function removeRealmRole(string $realm, string $userId, RoleRepresentation $role): bool
    {
        $roles = new RoleCollection();
        $roles->add($role);
        return $this->executeCommand(
            HttpMethodEnum::DELETE,
            'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm',
            $roles
        );
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function clientRoles(string $realm, string $clientUuid, string $userId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid, RoleCollection::class);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function availableClientRoles(string $realm, string $clientUuid, string $userId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid.'/available', RoleCollection::class);
    }

    public function addClientRole(string $realm, string $clientUuid, string $userId, RoleRepresentation $role): bool
    {
        $roles = new RoleCollection();
        $roles->add($role);
        return $this->executeCommand(
            HttpMethodEnum::POST,
            'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid,
            $roles
        );
    }

    public function removeClientRole(string $realm, string $clientUuid, string $userId, RoleRepresentation $role): bool
    {
        $roles = new RoleCollection();
        $roles->add($role);
        return $this->executeCommand(
            HttpMethodEnum::DELETE,
            'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid,
            $roles
        );
    }

    public function getProfileConfig(string $realm): ?UPConfig
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/profile', UPConfig::class);
    }

    public function getProfileMetadata(string $realm): ?UserProfileMetadata
    {
        return $this->executeQuery('admin/realms/'.$realm.'/users/profile/metadata', UserProfileMetadata::class);
    }

    public function resetPassword(string $realm, string $userId): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/users/'.$userId.'/reset-password');
    }

    public function sendVerifyEmail(string $realm, string $userId, array $parameters): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::PUT,
            'admin/realms/'.$realm.'/users/'.$userId.'/send-verify-email',
            $parameters
        );
    }
}
