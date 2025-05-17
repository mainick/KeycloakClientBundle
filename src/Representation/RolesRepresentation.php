<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Collection\RealmCollection;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class RolesRepresentation extends Representation
{
    public function __construct(
        public ?RealmCollection $realm = null,
        public ?Map $client = null,
        public ?Map $application = null,
    ) {
    }
}
