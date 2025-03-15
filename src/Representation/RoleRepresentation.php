<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class RoleRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $name = null,
        public ?string $description = null,
        public ?bool $scopeParamRequired = null,
        public ?bool $composite = null,
        public ?Composites $composites = null,
        public ?bool $clientRole = null,
        public ?string $containerId = null,
        public ?Map $attributes = null,
    ) {
    }
}
