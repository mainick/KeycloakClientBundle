<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

final readonly class UserRepresentationDTO
{
    /**
     * @param array<string>                        $attributes
     * @param RoleRepresentationDTO[]|null         $realmRoles
     * @param RoleRepresentationDTO[]|null         $clientRoles
     * @param RoleRepresentationDTO[]|null         $applicationRoles
     * @param GroupRepresentationDTO[]|null        $groups
     * @param ScopeRepresentationDTO[]|null        $scope
     * @param RoleRepresentationDTO[]|null         $authorizedPartyRoles roles of the client that requested the token (`resource_access[azp]`)
     * @param OrganizationRepresentationDTO[]|null $organizations
     * @param array<string,mixed>|null             $claims               the raw claims the DTO was built from
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
        public ?string $picture = null,
        public ?string $authorizedParty = null,
        public ?array $authorizedPartyRoles = null,
        public ?array $organizations = null,
        public ?string $issuer = null,
        public ?int $expiresAt = null,
        public ?array $claims = null,
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
                if (is_array($client_rif['roles'] ?? null)) {
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

        $authorized_party = isset($data['azp']) && is_string($data['azp']) && '' !== $data['azp'] ? $data['azp'] : null;
        $authorized_party_roles = [];
        if (null !== $authorized_party && is_array($data['resource_access'][$authorized_party]['roles'] ?? null)) {
            foreach ($data['resource_access'][$authorized_party]['roles'] as $role_name) {
                $dummy = ['name' => $role_name];
                $authorized_party_roles[] = RoleRepresentationDTO::fromArray($dummy);
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
            picture: $data['picture'] ?? $data['attributes']['picture'] ?? null,
            authorizedParty: $authorized_party,
            authorizedPartyRoles: count($authorized_party_roles) ? $authorized_party_roles : null,
            organizations: OrganizationRepresentationDTO::listFromClaim($data['organization'] ?? null),
            issuer: isset($data['iss']) && is_string($data['iss']) ? $data['iss'] : null,
            expiresAt: isset($data['exp']) && is_numeric($data['exp']) ? (int) $data['exp'] : null,
            claims: $data,
        );
    }
}
