<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\DTO\ProtocolMapperRepresentationDTO;
use Mainick\KeycloakClientBundle\Representation\Collection\ProtocolMapperCollection;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class ClientRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $clientId = null,
        public ?string $name = null,
        public ?string $description = null,
        public ?string $rootUrl = null,
        public ?string $adminUrl = null,
        public ?string $baseUrl = null,
        public ?bool $surrogateAuthRequired = null,
        public ?bool $enabled = null,
        public ?bool $alwaysDisplayInConsole = null,
        public ?string $clientAuthenticatorType = null,
        public ?string $secret = null,
        public ?string $registrationAccessToken = null,
        /** @var string[]|null */
        public ?array $redirectUris = null,
        /** @var string[]|null */
        public ?array $webOrigins = null,
        public ?int $notBefore = null,
        public ?bool $bearerOnly = null,
        public ?bool $consentRequired = null,
        public ?bool $standardFlowEnabled = null,
        public ?bool $implicitFlowEnabled = null,
        public ?bool $directAccessGrantsEnabled = null,
        public ?bool $serviceAccountsEnabled = null,
        public ?bool $authorizationServicesEnabled = null,
        public ?bool $publicClient = null,
        public ?bool $frontchannelLogout = null,
        public ?string $protocol = null,
        public ?Map $attributes = null,
        public ?Map $authenticationFlowBindingOverrides = null,
        public ?bool $fullScopeAllowed = null,
        public ?int $nodeReRegistrationTimeout = null,
        public ?Map $registeredNodes = null,
        public ?ProtocolMapperCollection $protocolMappers = null,
        /** @var string[]|null */
        public ?array $defaultClientScopes = null,
        /** @var string[]|null */
        public ?array $optionalClientScopes = null,
        public ?Map $access = null,
        public ?string $origin = null
    ) {
    }
}
