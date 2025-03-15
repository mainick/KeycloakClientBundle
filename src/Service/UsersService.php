<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserSessionCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UPConfig;
use Mainick\KeycloakClientBundle\Representation\UserProfileMetadata;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserSessionRepresentation;
use Mainick\KeycloakClientBundle\Service\Service;

final class UsersService extends Service
{
    public function all(string $realm, ?Criteria $criteria): ?UserCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/users', $criteria);
        if (null === $items) {
            return null;
        }

        $users = new UserCollection();
        foreach ($items as $item) {
            $users->add(UserRepresentation::from($item));
        }

        return $users;
    }

    public function get(string $realm, string $userId): ?UserRepresentation
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId);
        if (null === $item) {
            return null;
        }

        return UserRepresentation::from($item);
    }

    public function count(string $realm, ?Criteria $criteria): int
    {
        $count = $this->executeQuery('admin/realms/'.$realm.'/users/count', $criteria);
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

    public function groups(string $realm, string $userId): ?GroupCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/groups');
        if (null === $items) {
            return null;
        }

        $groups = new GroupCollection();
        foreach ($items as $item) {
            $groups->add(GroupRepresentation::from($item));
        }

        return $groups;
    }

    public function groupsCount(string $realm, string $userId): int
    {
        $count = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/groups/count');
        if (null === $count) {
            return 0;
        }

        return (int) $count;
    }

    public function realmRoles(string $realm, string $userId): ?RoleCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm');
        if (null === $items) {
            return null;
        }

        $roles = new RoleCollection();
        foreach ($items as $item) {
            $roles->add(RoleRepresentation::from($item));
        }

        return $roles;
    }

    public function availableRealmRoles(string $realm, string $userId): ?RoleCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm/available');
        if (null === $items) {
            return null;
        }

        $roles = new RoleCollection();
        foreach ($items as $item) {
            $roles->add(RoleRepresentation::from($item));
        }

        return $roles;
    }

    public function sessions(string $realm, string $userId): ?UserSessionCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/sessions');
        if (null === $items) {
            return null;
        }

        $userSessions = new UserSessionCollection();
        foreach ($items as $item) {
            $userSessions->add(UserSessionRepresentation::from($item));
        }

        return $userSessions;
    }

    public function offlineSessions(string $realm, string $userId, string $clientId): ?UserSessionCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/users/'.$userId.'/offline-sessions/'.$clientId);
        if (null === $items) {
            return null;
        }

        $userSessions = new UserSessionCollection();
        foreach ($items as $item) {
            $userSessions->add(UserSessionRepresentation::from($item));
        }

        return $userSessions;
    }

    public function joinGroup(string $realm, string $userId, string $groupId): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/users/'.$userId.'/groups/'.$groupId);
    }

    public function leaveGroup(string $realm, string $userId, string $groupId): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/users/'.$userId.'/groups/'.$groupId);
    }

    public function addRealmRole(string $realm, string $userId, RoleRepresentation $role): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::POST,
            'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm',
            $role
        );
    }

    public function removeRealmRole(string $realm, string $userId, RoleRepresentation $role): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::DELETE,
            'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm',
            $role
        );
    }

    public function getProfileConfig(string $realm): ?UPConfig
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/users/profile');
        if (null === $item) {
            return null;
        }

        return UPConfig::from($item);
    }

    public function getProfileMetadata(string $realm): ?UserProfileMetadata
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/users/profile/metadata');
        if (null === $item) {
            return null;
        }

        return UserProfileMetadata::from($item);
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
