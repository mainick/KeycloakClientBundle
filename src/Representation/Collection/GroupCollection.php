<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;

/**
 * @extends Collection<GroupRepresentation>
 */
class GroupCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return GroupRepresentation::class;
    }
}
