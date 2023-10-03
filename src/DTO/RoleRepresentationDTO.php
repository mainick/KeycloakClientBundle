<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

class RoleRepresentationDTO
{
    /**
     * @param array<string> $attributes
     */
    public function __construct(
        public string $name,
        public ?string $id,
        public ?string $description,
        public ?bool $composite,
        public ?bool $clientRole,
        public ?array $attributes,
    ) {
    }

    /**
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            name: $data['name'],
            id: $data['id'] ?? null,
            description: $data['description'] ?? null,
            composite: $data['composite'] ?? null,
            clientRole: $data['clientRole'] ?? null,
            attributes: $data['attributes'] ?? null,
        );
    }
}
