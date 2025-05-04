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
}
