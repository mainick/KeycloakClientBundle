<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Representation;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class UserProfileAttributeGroupMetadata extends Representation
{
    public function __construct(
        public ?string $name = null,
        public ?string $displayHeader = null,
        public ?string $displayDescription = null,
        public ?Map $annotations = null,
    ) {
    }
}
