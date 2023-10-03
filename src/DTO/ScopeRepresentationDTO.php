<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

final readonly class ScopeRepresentationDTO
{
    public function __construct(
        public string $name,
        public ?string $id,
    ) {
    }

    /**
     * @param array<string,string> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            name: $data['name'],
            id: $data['id'] ?? null,
        );
    }
}
