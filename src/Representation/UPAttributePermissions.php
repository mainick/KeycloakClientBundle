<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class UPAttributePermissions extends Representation
{
    public function __construct(
        public ?Map $view = null,
        public ?Map $edit = null,
    ) {
    }
}
