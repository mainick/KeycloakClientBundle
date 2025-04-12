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
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;

final class ClientsService extends Service
{
    /**
     * @return ClientCollection<ClientRepresentation>|null
     */
    public function all(string $realm, ?Criteria $criteria = null): ?ClientCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients', ClientCollection::class, $criteria);
    }

    public function get(string $realm, string $clientUuid): ?ClientRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientUuid, ClientRepresentation::class);
    }

    public function create(string $realm, ClientRepresentation $client): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/clients', $client);
    }

    public function update(string $realm, string $clientUuid, ClientRepresentation $client): bool
    {
        return $this->executeCommand(HttpMethodEnum::PUT, 'admin/realms/'.$realm.'/clients/'.$clientUuid, $client);
    }

    public function delete(string $realm, string $clientUuid): bool
    {
        return $this->executeCommand(HttpMethodEnum::DELETE, 'admin/realms/'.$realm.'/clients/'.$clientUuid);
    }

    public function getClientSecret(string $realm, string $clientUuid): ?CredentialRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientUuid.'/client-secret', CredentialRepresentation::class);
    }

    public function getUserSessions(string $realm, string $clientUuid): ?UserSessionCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientUuid.'/user-sessions', UserSessionCollection::class);
    }

    /**
     * @return RoleCollection<RoleRepresentation>|null
     */
    public function roles(string $realm, string $clientUuid): ?RoleCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles', RoleCollection::class);
    }

    public function role(string $realm, string $clientUuid, string $roleName): ?RoleRepresentation
    {
        return $this->executeQuery('admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName, RoleRepresentation::class);
    }

    public function createRole(string $realm, string $clientUuid, RoleRepresentation $role): bool
    {
        return $this->executeCommand(HttpMethodEnum::POST, 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles', $role);

    }

    public function updateRole(string $realm, string $clientUuid, string $roleName, RoleRepresentation $role): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::PUT,
            'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName,
            $role
        );
    }

    public function deleteRole(string $realm, string $clientUuid, string $roleName): bool
    {
        return $this->executeCommand(
            HttpMethodEnum::DELETE,
            'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName
        );
    }

    /**
     * @return GroupCollection<GroupRepresentation>|null
     */
    public function getRoleGroups(
        string $realm,
        string $clientUuid,
        string $roleName,
        ?Criteria $criteria = null
    ): ?GroupCollection
    {
        return $this->executeQuery(
            'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName.'/groups',
            GroupCollection::class,
            $criteria
        );
    }

    /**
     * @return UserCollection<UserRepresentation>|null
     */
    public function getRoleUsers(
        string $realm,
        string $clientUuid,
        string $roleName,
        ?Criteria $criteria = null
    ): ?UserCollection
    {
        return $this->executeQuery(
            'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName.'/users',
            UserCollection::class,
            $criteria
        );
    }

}
