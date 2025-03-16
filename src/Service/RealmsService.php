<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\Collection\RealmCollection;
use Mainick\KeycloakClientBundle\Representation\RealmRepresentation;
use Mainick\KeycloakClientBundle\Service\Service;

final class RealmsService extends Service
{
    public function all(?Criteria $criteria): ?RealmCollection
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
