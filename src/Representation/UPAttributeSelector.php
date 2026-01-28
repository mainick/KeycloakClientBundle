<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class UPAttributeSelector extends Representation
{
    /**
     * @param ?Map<string> $scopes
     */
    public function __construct(public ?Map $scopes = null)
    {
    }
}
