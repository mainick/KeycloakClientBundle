<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\UserProfileAttributeMetadata;

/**
 * @extends Collection<UserProfileAttributeMetadata>
 */
class UserProfileAttributeMetadataCollection extends Collection
{
    /**
     * @inheritDoc
     */
    public static function getRepresentationClass(): string
    {
        return UserProfileAttributeMetadata::class;
    }
}
