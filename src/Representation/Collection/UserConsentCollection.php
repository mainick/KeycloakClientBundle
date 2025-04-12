<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\UserConsentRepresentation;

/**
 * @extends Collection<UserConsentRepresentation>
 */
class UserConsentCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return UserConsentRepresentation::class;
    }
}
