<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\ClientRepresentation;
use Mainick\KeycloakClientBundle\Representation\Collection\ClientCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserSessionCollection;
use Mainick\KeycloakClientBundle\Representation\CredentialRepresentation;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserSessionRepresentation;
use Mainick\KeycloakClientBundle\Service\Service;

final class ClientsService extends Service
{
    public function all(string $realm, ?Criteria $criteria): ?ClientCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/clients', $criteria);
        if (null === $items) {
            return null;
        }

        $clients = new ClientCollection();
        foreach ($items as $item) {
            $clients->add(ClientRepresentation::from($item));
        }

        return $clients;
    }

    public function get(string $realm, string $clientId): ?ClientRepresentation
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId);
        if (null === $item) {
            return null;
        }

        return ClientRepresentation::from($item);
    }

    public function create(string $realm, ClientRepresentation $client): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/clients', $client);
    }

    public function update(string $realm, string $clientId, ClientRepresentation $client): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/clients/'.$clientId, $client);
    }

    public function delete(string $realm, string $clientId): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/clients/'.$clientId);
    }

    public function getClientSecret(string $realm, string $clientId): ?CredentialRepresentation
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/client-secret');
        if (null === $item) {
            return null;
        }

        return CredentialRepresentation::from($item);
    }

    public function getUserSessions(string $realm, string $clientId): ?UserSessionCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/user-sessions');
        if (null === $items) {
            return null;
        }

        $userSessions = new UserSessionCollection();
        foreach ($items as $item) {
            $userSessions->add(UserSessionRepresentation::from($item));
        }

        return $userSessions;
    }

    public function roles(string $realm, string $clientId): ?RoleCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/roles');
        if (null === $items) {
            return null;
        }

        $roles = new RoleCollection();
        foreach ($items as $item) {
            $roles->add(RoleRepresentation::from($item));
        }

        return $roles;
    }

    public function role(string $realm, string $clientId, string $roleName): ?RoleRepresentation
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName);
        if (null === $item) {
            return null;
        }

        return RoleRepresentation::from($item);
    }

    public function createRole(string $realm, string $clientId, RoleRepresentation $role): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/clients/'.$clientId.'/roles', $role);

    }

    public function updateRole(string $realm, string $clientId, string $roleName, RoleRepresentation $role): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::PUT,
            'admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName,
            $role
        );
    }

    public function deleteRole(string $realm, string $clientId, string $roleName): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::DELETE,
            'admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName
        );
    }

    public function getRoleGroups(
        string $realm,
        string $clientId,
        string $roleName,
        ?Criteria $criteria
    ): ?GroupCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName.'/groups', $criteria);
        if (null === $items) {
            return null;
        }

        $groups = new GroupCollection();
        foreach ($items as $item) {
            $groups->add(GroupRepresentation::from($item));
        }

        return $groups;
    }

    public function getRoleUsers(
        string $realm,
        string $clientId,
        string $roleName,
        ?Criteria $criteria
    ): ?UserCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName.'/users', $criteria);
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
