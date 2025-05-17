<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\UserRepresentation;

/**
 * @extends Collection<UserRepresentation>
 */
class UserCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return UserRepresentation::class;
    }
}
