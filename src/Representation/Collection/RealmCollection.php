<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\RealmRepresentation;

/**
 * @extends Collection<RealmRepresentation>
 */
class RealmCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return RealmRepresentation::class;
    }
}
