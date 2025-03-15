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
        $items = $this->executeQuery('admin/realms/'.$realm.'/roles', $criteria);
        if (null === $items) {
            return null;
        }

        $roles = new RoleCollection();
        foreach ($items as $item) {
            $roles->add(RoleRepresentation::from($item));
        }

        return $roles;
    }

    public function get(string $realm, string $roleName): ?RoleRepresentation
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName);
        if (null === $item) {
            return null;
        }

        return RoleRepresentation::from($item);
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
        $items = $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName.'/groups', $criteria);
        if (null === $items) {
            return null;
        }

        $groups = new GroupCollection();
        foreach ($items as $item) {
            $groups->add(GroupRepresentation::from($item));
        }

        return $groups;
    }

    public function users(string $realm, string $roleName, ?Criteria $criteria): ?UserCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/roles/'.$roleName.'/users', $criteria);
        if (null === $items) {
            return null;
        }

        $users = new UserCollection();
        foreach ($items as $item) {
            $users->add(UserRepresentation::from($item));
        }

        return $users;
    }

}
