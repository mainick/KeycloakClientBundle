<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;

final class GroupsService extends Service
{
    /**
     * @return GroupCollection<GroupRepresentation>|null
     */
    public function all(string $realm, ?Criteria $criteria = null): ?GroupCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups', GroupCollection::class, $criteria);
    }

    public function count(string $realm, ?Criteria $criteria = null): int
    {
        $count = $this->executeQuery('admin/realms/'.$realm.'/groups/count', 'array', $criteria);
        if (null === $count) {
            return 0;
        }

        return (int) $count;
    }

    /**
     * @return GroupCollection<GroupRepresentation>|null
     */
    public function children(string $realm, string $groupId, ?Criteria $criteria = null): ?GroupCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/children', GroupCollection::class, $criteria);
    }

    public function get(string $realm, string $groupId): ?GroupRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId, GroupRepresentation::class);
    }

    public function create(string $realm, GroupRepresentation $group): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/groups', $group);
    }

    public function createChild(string $realm, string $parentGroupId, GroupRepresentation $group): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/groups/'.$parentGroupId.'/children', $group);
    }

    public function update(string $realm, string $groupId, GroupRepresentation $group): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/groups/'.$groupId, $group);
    }

    public function delete(string $realm, string $groupId): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/groups/'.$groupId);
    }

    /**
     * @return UserCollection<UserRepresentation>|null
     */
    public function users(string $realm, string $groupId): ?UserCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/members', UserCollection::class);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function realmRoles(string $realm, string $groupId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm', RoleCollection::class);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function availableRealmRoles(string $realm, string $groupId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm/available', RoleCollection::class);
    }

    public function addRealmRole(string $realm, string $groupId, RoleRepresentation $role): bool
    {
        $roles = new RoleCollection();
        $roles->add($role);
        return $this->executeCommand(
            HttpMethodEnum::POST,
            'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm',
            $roles
        );
    }

    public function removeRealmRole(string $realm, string $groupId, RoleRepresentation $role): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::DELETE,
            'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm',
            $role
        );
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function clientRoles(string $realm, string $clientUuid, string $groupId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid, RoleCollection::class);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function availableClientRoles(string $realm, string $clientUuid, string $groupId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid.'/available', RoleCollection::class);
    }

    public function addClientRole(string $realm, string $clientUuid, string $groupId, RoleRepresentation $role): bool
    {
        $roles = new RoleCollection();
        $roles->add($role);
        return $this->executeCommand(
            HttpMethodEnum::POST,
            'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid,
            $roles
        );
    }

    public function removeClientRole(string $realm, string $clientUuid, string $groupId, RoleRepresentation $role): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::DELETE,
            'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid,
            $role
        );
    }
}
