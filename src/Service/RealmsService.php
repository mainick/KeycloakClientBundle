<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RealmCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RealmRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;

final class RealmsService extends Service
{
    /**
     * @return RealmCollection<RealmRepresentation>|null
     */
    public function all(?Criteria $criteria = null): ?RealmCollection
    {
        return $this->executeQuery('admin/realms', RealmCollection::class, $criteria);
    }

    public function get(string $realm): ?RealmRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm, RealmRepresentation::class);
    }

    public function create(RealmRepresentation $realm): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/', $realm);
    }

    public function update(string $realm, RealmRepresentation $realmUpdate): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm, $realmUpdate);
    }

    public function delete(string $realm): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function roles(string $realm): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles', RoleCollection::class);
    }

    public function role(string $realm, string $roleName): ?RoleRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName, RoleRepresentation::class);
    }

    public function createRole(string $realm, RoleRepresentation $role): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/roles', $role);
    }

    public function updateRole(string $realm, string $roleName, RoleRepresentation $role): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/roles/'.$roleName, $role);
    }

    public function deleteRole(string $realm, string $roleName): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/roles/'.$roleName);
    }

    /**
     * @return GroupCollection<GroupRepresentation>|null
     */
    public function getRoleGroups(string $realm, string $roleName, ?Criteria $criteria = null): ?GroupCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName.'/groups', GroupCollection::class, $criteria);
    }

    /**
     * @return UserCollection<UserRepresentation>|null
     */
    public function getRoleUsers(string $realm, string $roleName, ?Criteria $criteria = null): ?UserCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName.'/users', UserCollection::class, $criteria);
    }
}
