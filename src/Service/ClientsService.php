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
        return $this->executeQuery('admin/realms/'.$realm.'/clients', ClientCollection::class, $criteria);
    }

    public function get(string $realm, string $clientId): ?ClientRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId, ClientRepresentation::class);
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
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/client-secret', CredentialRepresentation::class);
    }

    public function getUserSessions(string $realm, string $clientId): ?UserSessionCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/user-sessions', UserSessionCollection::class);
    }

    public function roles(string $realm, string $clientId): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/roles', RoleCollection::class);
    }

    public function role(string $realm, string $clientId, string $roleName): ?RoleRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName, RoleRepresentation::class);
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
        return $this->executeQuery(
            'admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName.'/groups',
            GroupCollection::class,
            $criteria
        );
    }

    public function getRoleUsers(
        string $realm,
        string $clientId,
        string $roleName,
        ?Criteria $criteria
    ): ?UserCollection
    {
        return $this->executeQuery(
            'admin/realms/'.$realm.'/clients/'.$clientId.'/roles/'.$roleName.'/users',
            UserCollection::class,
            $criteria
        );
    }

}
