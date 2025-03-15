<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class Composites extends Representation
{
    public function __construct(
        public ?RealCollection $realm = null,
        public ?Map $client = null,
        public ?Map $application = null,
    ) {
    }
}
