<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class ProtocolMapperRepresentation extends Representation
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
}
