<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\UPAttribute;

/**
 * @extends Collection<UPAttribute>
 */
class UPAttributeCollection extends Collection
{
    public static function getRepresentationClass(): string
    {
        return UPAttribute::class;
    }
}
