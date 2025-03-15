<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Representation;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class CredentialRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $type = null,
        public ?string $userLabel = null,
        public ?int $createdDate = null,
        public ?string $secretData = null,
        public ?string $credentialData = null,
        public ?int $priority = null,
        public ?string $value = null,
        public ?bool $temporary = null,
        public ?string $device = null,
        public ?string $hashedSaltedValue = null,
        public ?string $salt = null,
        public ?int $hashIterations = null,
        public ?int $counter = null,
        public ?string $algorithm = null,
        public ?int $digits = null,
        public ?int $period = null,
        public ?Map $config = null
    )
    {
    }
}
