<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Collection\ProtocolMapperCollection;
use Mainick\KeycloakClientBundle\Representation\Representation;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class ClientScopeRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $name = null,
        public ?string $description = null,
        public ?string $protocol = null,
        public ?Map $attributes = null,
        public ?ProtocolMapperCollection $protocolMappers = null,
    ) {
    }
}
