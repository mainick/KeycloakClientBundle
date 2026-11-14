<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

/**
 * An organization the user belongs to, read from the `organization` claim.
 *
 * Keycloak emits the claim either as a list of aliases (default mapper), as a single alias
 * (non multivalued mapper) or as a map alias => {id, attributes} when "Add organization id"
 * or "Add organization attributes" are enabled.
 */
final readonly class OrganizationRepresentationDTO
{
    /**
     * @param array<string,mixed>|null $attributes
     */
    public function __construct(
        public string $alias,
        public ?string $id = null,
        public ?array $attributes = null,
    ) {
    }

    /**
     * @return self[]|null
     */
    public static function listFromClaim(mixed $claim): ?array
    {
        if (is_string($claim) && '' !== $claim) {
            return [new self($claim)];
        }

        if (!is_array($claim) || [] === $claim) {
            return null;
        }

        $organizations = [];
        if (array_is_list($claim)) {
            foreach ($claim as $alias) {
                if (is_string($alias) && '' !== $alias) {
                    $organizations[] = new self($alias);
                }
            }

            return count($organizations) ? $organizations : null;
        }

        foreach ($claim as $alias => $details) {
            $details = is_array($details) ? $details : [];
            $id = isset($details['id']) && is_string($details['id']) ? $details['id'] : null;
            unset($details['id']);
            $organizations[] = new self((string) $alias, $id, count($details) ? $details : null);
        }

        return $organizations;
    }
}
