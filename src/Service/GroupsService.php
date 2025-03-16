<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Service\Service;

final class GroupsService extends Service
{
    public function all(string $realm, ?Criteria $criteria): ?GroupCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups', GroupCollection::class, $criteria);
    }

    public function count(string $realm, ?Criteria $criteria): int
    {
        $count = $this->executeQuery('admin/realms/'.$realm.'/groups/count', 'array', $criteria);
        if (null === $count) {
            return 0;
        }

        return (int) $count;
    }

    public function children(string $realm, string $groupId, ?Criteria $criteria): ?GroupCollection
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

    public function users(string $realm, string $groupId): ?UserCollection
    {
        return $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/members', UserCollection::class);
    }
}
