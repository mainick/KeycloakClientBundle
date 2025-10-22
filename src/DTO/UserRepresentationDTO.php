<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

final readonly class UserRepresentationDTO
{
    /**
     * @param array<string>                 $attributes
     * @param RoleRepresentationDTO[]|null  $realmRoles
     * @param RoleRepresentationDTO[]|null  $clientRoles
     * @param RoleRepresentationDTO[]|null  $applicationRoles
     * @param GroupRepresentationDTO[]|null $groups
     * @param ScopeRepresentationDTO[]|null $scope
     */
    public function __construct(
        public string $id,
        public string $username,
        public bool $emailVerified,
        public ?string $name,
        public ?string $firstName,
        public ?string $lastName,
        public string $email,
        public ?bool $enabled,
        public ?int $createdTimestamp,
        public ?int $updatedAt,
        public ?array $attributes,
        public ?array $realmRoles,
        public ?array $clientRoles,
        public ?array $applicationRoles,
        public ?array $groups,
        public ?array $scope,
    ) {
    }

    /**
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data, ?string $client_id = null): self
    {
        $realm_roles = [];
        if (isset($data['realm_access']['roles'])) {
            foreach ($data['realm_access']['roles'] as $role_name) {
                $dummy = ['name' => $role_name];
                $realm_roles[] = RoleRepresentationDTO::fromArray($dummy);
            }
        }

        $client_roles = [];
        if (isset($data['resource_access'])) {
            foreach ($data['resource_access'] as $client_rif) {
                if (isset($client_rif['roles'])) {
                    foreach ($client_rif['roles'] as $role_name) {
                        $dummy = ['name' => $role_name];
                        $client_roles[] = RoleRepresentationDTO::fromArray($dummy);
                    }
                }
            }
        }

        $application_roles = [];
        if ($client_id && isset($data['resource_access'][$client_id]['roles'])) {
            foreach ($data['resource_access'][$client_id]['roles'] as $role_name) {
                $dummy = ['name' => $role_name];
                $application_roles[] = RoleRepresentationDTO::fromArray($dummy);
            }
        }

        $groups = [];
        foreach ($data['groups'] ?? [] as $group_name) {
            $dummy = ['name' => $group_name];
            $groups[] = GroupRepresentationDTO::fromArray($dummy);
        }

        $scope = [];
        if (isset($data['scope'])) {
            foreach (explode(' ', $data['scope']) as $scope_name) {
                $dummy = ['name' => $scope_name];
                $scope[] = ScopeRepresentationDTO::fromArray($dummy);
            }
        }

        return new self(
            id: $data['sub'],
            username: $data['preferred_username'],
            emailVerified: $data['email_verified'],
            name: $data['name'] ?? null,
            firstName: $data['given_name'] ?? null,
            lastName: $data['family_name'] ?? null,
            email: $data['email'],
            enabled: $data['enabled'] ?? null,
            createdTimestamp: $data['createdTimestamp'] ?? null,
            updatedAt: $data['updated_at'] ?? null,
            attributes: $data['attributes'] ?? null,
            realmRoles: count($realm_roles) ? $realm_roles : null,
            clientRoles: count($client_roles) ? $client_roles : null,
            applicationRoles: count($application_roles) ? $application_roles : null,
            groups: count($groups) ? $groups : null,
            scope: count($scope) ? $scope : null,
        );
    }
}
