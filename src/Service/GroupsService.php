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
        $items = $this->executeQuery('admin/realms/'.$realm.'/groups', $criteria);
        if (null === $items) {
            return null;
        }

        $groups = new GroupCollection();
        foreach ($items as $item) {
            $groups->add(GroupRepresentation::from($item));
        }

        return $groups;
    }

    public function count(string $realm, ?Criteria $criteria): int
    {
        $count = $this->executeQuery('admin/realms/'.$realm.'/groups/count', $criteria);
        if (null === $count) {
            return 0;
        }

        return (int) $count;
    }

    public function children(string $realm, string $groupId, ?Criteria $criteria): ?GroupCollection
    {
        $items = $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/children', $criteria);
        if (null === $items) {
            return null;
        }

        $groups = new GroupCollection();
        foreach ($items as $item) {
            $groups->add(GroupRepresentation::from($item));
        }

        return $groups;
    }

    public function get(string $realm, string $groupId): ?GroupRepresentation
    {
        $item = $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId);
        if (null === $item) {
            return null;
        }

        return GroupRepresentation::from($item);
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
        $items = $this->executeQuery('admin/realms/'.$realm.'/groups/'.$groupId.'/members');
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
