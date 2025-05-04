<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Collection\UPAttributeCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UPGroupCollection;
use Mainick\KeycloakClientBundle\Representation\Representation;

final class UPConfig extends Representation
{
    public function __construct(
        public ?UPAttributeCollection $attributes = null,
        public ?UPGroupCollection $groups = null,
        public ?UnmanagedAttributePolicyEnum $unmanagedAttributePolicy = null,
    ) {
    }
}
