<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Service\Service;

final class RolesService extends Service
{
    public function all(string $realm, ?Criteria $criteria): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles', RoleCollection::class, $criteria);
    }

    public function get(string $realm, string $roleName): ?RoleRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName, RoleRepresentation::class);
    }

    public function create(string $realm, RoleRepresentation $role): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/roles', $role);
    }

    public function update(string $realm, string $roleName, RoleRepresentation $role): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/roles/'.$roleName, $role);
    }

    public function delete(string $realm, string $roleName): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/roles/'.$roleName);
    }

    public function groups(string $realm, string $roleName, ?Criteria $criteria): ?GroupCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName.'/groups', GroupCollection::class, $criteria);
    }

    public function users(string $realm, string $roleName, ?Criteria $criteria): ?UserCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName.'/users', UserCollection::class, $criteria);
    }

}
