<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Collection\UserProfileAttributeGroupMetadataCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserProfileAttributeMetadataCollection;
use Mainick\KeycloakClientBundle\Representation\Representation;

final class UserProfileMetadata extends Representation
{
    public function __construct(
        public ?UserProfileAttributeMetadataCollection $userProfileAttributeMetadata = null,
        public ?UserProfileAttributeGroupMetadataCollection $userProfileAttributeGroupMetadata = null,
    ) {
    }
}
