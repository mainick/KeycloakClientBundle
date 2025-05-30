<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;

/**
 * @extends Collection<RoleRepresentation>
 */
class RoleCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return RoleRepresentation::class;
    }
}
