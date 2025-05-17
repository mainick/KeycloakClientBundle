<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\ClientScopeRepresentation;

/**
 * @extends Collection<ClientScopeRepresentation>
 */
class ClientScopeCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return ClientScopeRepresentation::class;
    }
}
