<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class ProtocolMapperRepresentationDTO
{
    public function __construct(
        public ?string $id = null,
        public ?string $name = null,
        public ?string $protocol = null,
        public ?string $protocolMapper = null,
        public ?bool $consentRequired = null,
        public ?string $consentText = null,
        public ?Map $config = null
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'] ?: null,
            name: $data['name'] ?: null,
            protocol: $data['protocol'] ?: null,
            protocolMapper: $data['protocolMapper'] ?: null,
            consentRequired: $data['consentRequired'] ?: null,
            consentText: $data['consentText'] ?: null,
            config: $data['config'] ?: null
        );
    }
}
