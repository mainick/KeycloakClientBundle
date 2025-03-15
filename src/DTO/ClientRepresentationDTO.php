<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

use Mainick\KeycloakClientBundle\Representation\Collection\ProtocolMapperCollection;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final readonly class ClientRepresentationDTO
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
        public ?ProtocolMapperCollection $protocol = null,
        public ?Map $attributes = null,
        public ?Map $authenticationFlowBindingOverrides = null,
        public ?bool $fullScopeAllowed = null,
        public ?int $nodeReRegistrationTimeout = null,
        public ?Map $registeredNodes = null,
        public array $protocolMappers,
        /** @var string[]|null */
        public ?array $defaultClientScopes = null,
        /** @var string[]|null */
        public ?array $optionalClientScopes = null,
        public ?Map $access = null,
        public ?string $origin = null
    ) {
    }

    public static function fromArray(array $data): self
    {
        $protocolMappers = [];
        foreach ($data['protocolMappers'] as $protocolMapper) {
            $protocolMappers[] = ProtocolMapperRepresentationDTO::fromArray($protocolMapper);
        }

        return new self(
            id: $data['id'] ?: null,
            clientId: $data['clientId'] ?: null,
            name: $data['name'] ?: null,
            description: $data['description'] ?: null,
            rootUrl: $data['rootUrl'] ?: null,
            adminUrl: $data['adminUrl'] ?: null,
            baseUrl: $data['baseUrl'] ?: null,
            surrogateAuthRequired: $data['surrogateAuthRequired'] ?: null,
            enabled: $data['enabled'] ?: null,
            alwaysDisplayInConsole: $data['alwaysDisplayInConsole'] ?: null,
            clientAuthenticatorType: $data['clientAuthenticatorType'] ?: null,
            secret: $data['secret'] ?: null,
            registrationAccessToken: $data['registrationAccessToken'] ?: null,
            redirectUris: $data['redirectUris'] ?: null,
            webOrigins: $data['webOrigins'],
            notBefore: $data['notBefore'] ?: null,
            bearerOnly: $data['bearerOnly'] ?: null,
            consentRequired: $data['consentRequired'] ?: null,
            standardFlowEnabled: $data['standardFlowEnabled'] ?: null,
            implicitFlowEnabled: $data['implicitFlowEnabled'] ?: null,
            directAccessGrantsEnabled: $data['directAccessGrantsEnabled'] ?: null,
            serviceAccountsEnabled: $data['serviceAccountsEnabled'] ?: null,
            authorizationServicesEnabled: $data['authorizationServicesEnabled'] ?: null,
            publicClient: $data['publicClient'] ?: null,
            frontchannelLogout: $data['frontchannelLogout'] ?: null,
            protocol: $data['protocol'] ?: null,
            attributes: $data['attributes'] ?: null,
            authenticationFlowBindingOverrides: $data['authenticationFlowBindingOverrides'] ?: null,
            fullScopeAllowed: $data['fullScopeAllowed'] ?: null,
            nodeReRegistrationTimeout: $data['nodeReRegistrationTimeout'] ?: null,
            registeredNodes: $data['registeredNodes'] ?: null,
            protocolMappers: $protocolMappers,
            defaultClientScopes: $data['defaultClientScopes'],
            optionalClientScopes: $data['optionalClientScopes'] ?: null,
            access: $data['access'] ?: null,
            origin: $data['origin'] ?: null
        );
    }
}
