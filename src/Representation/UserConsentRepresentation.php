<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Representation;

class UserConsentRepresentation extends Representation
{
    public function __construct(
        public ?string $clientId = null,
        /** @var string[]|null */
        public ?array $grantedClientScopes = null,
        public ?int $createdDate = null,
        public ?int $lastUpdatedDate = null,
        /** @var string[]|null */
        public ?array $grantedRealmRoles = null,
    ) {
    }
}
