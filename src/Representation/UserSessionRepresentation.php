<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Representation;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class UserSessionRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $username = null,
        public ?string $userId = null,
        public ?string $ipAddress = null,
        public ?int $start = null,
        public ?int $lastAccess = null,
        public ?bool $rememberMe = null,
        public ?Map $clients = null,
        public ?bool $transientUser = null,
    )
    {
    }
}
