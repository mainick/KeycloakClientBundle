<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\CredentialRepresentation;

/**
 * @extends Collection<CredentialRepresentation>
 */
class CredentialCollection extends Collection
{
    public static function getRepresentationClass(): string
    {
        return CredentialRepresentation::class;
    }
}
