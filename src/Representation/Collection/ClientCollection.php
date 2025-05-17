<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\ClientRepresentation;

/**
 * @extends Collection<ClientRepresentation>
 */
class ClientCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return ClientRepresentation::class;
    }
}
