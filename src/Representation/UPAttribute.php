<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Representation;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class UPAttribute extends Representation
{
    public function __construct(
        public ?string $name = null,
        public ?string $displayName = null,
        public ?Map $validations = null,
        public ?Map $annotations = null,
        public ?UPAttributeRequired $required = null,
        public ?UPAttributePermissions $permissions = null,
        public ?UPAttributeSelector $selector = null,
        public ?string $group = null,
        public ?bool $multivalued = null,
    ){
    }
}
