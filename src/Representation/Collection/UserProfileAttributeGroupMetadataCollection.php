<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\UserProfileAttributeGroupMetadata;

class UserProfileAttributeGroupMetadataCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return UserProfileAttributeGroupMetadata::class;
    }
}
