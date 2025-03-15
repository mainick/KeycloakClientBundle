<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\UserSessionRepresentation;

class UserSessionCollection extends Collection
{
    public static function getRepresentationClass(): string
    {
        return UserSessionRepresentation::class;
    }
}
