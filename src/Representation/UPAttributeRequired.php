<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class UPAttributeRequired extends Representation
{
    public function __construct(
        public ?Map $roles = null,
        public ?Map $scopes = null,
    ) {
    }
}
