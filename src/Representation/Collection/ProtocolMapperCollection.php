<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\ProtocolMapperRepresentation;

/**
 * @extends Collection<ProtocolMapperRepresentation>
 */
class ProtocolMapperCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return ProtocolMapperRepresentation::class;
    }
}
