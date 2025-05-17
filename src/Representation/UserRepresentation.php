<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Representation\Collection\CredentialCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserConsentCollection;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class UserRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $username = null,
        public ?string $firstName = null,
        public ?string $lastName = null,
        public ?string $email = null,
        public ?bool $emailVerified = null,
        public ?Map $attributes = null,
        public ?UserProfileMetadata $userProfileMetadata = null,
        public ?string $self = null,
        public ?string $origin = null,
        public ?int $createdTimestamp = null,
        public ?bool $enabled = null,
        public ?bool $totp = null,
        public ?string $federationLink = null,
        public ?string $serviceAccountClientId = null,
        public ?CredentialCollection $credentials = null,
        /** @var string[]|null */
        public ?array $disableableCredentialTypes = null,
        /** @var string[]|null */
        public ?array $requiredActions = null,
        //public ?FederatedIdentityCollection $federatedIdentities = null,
        /** @var string[]|null */
        public ?array $realmRoles = null,
        public ?Map $clientRoles = null,
        public ?UserConsentCollection $clientConsents = null,
        public ?int $notBefore = null,
        public ?Map $applicationRoles = null,
        //public ?SocialLinkCollection $socialLinks = null,
        /** @var string[]|null */
        public ?array $groups = null,
        public ?Map $access = null,
    ) {
    }
}
