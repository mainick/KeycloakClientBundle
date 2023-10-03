<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DTO;

final readonly class ClientRepresentationDTO
{
    public function __construct(
        public string $id,
        public string $clientId,
        public string $name,
        public string $description,
        public string $rootUrl,
        public string $adminUrl,
        public string $baseUrl,
        public bool $surrogateAuthRequired,
        public bool $enabled,
        public bool $alwaysDisplayInConsole,
        public string $clientAuthenticatorType,
        public string $secret,
        public array $redirectUris,
        public array $webOrigins,
        public int $notBefore,
        public bool $bearerOnly,
        public bool $consentRequired,
        public bool $standardFlowEnabled,
        public bool $implicitFlowEnabled,
        public bool $directAccessGrantsEnabled,
        public bool $serviceAccountsEnabled,
        public bool $authorizationServicesEnabled,
        public bool $publicClient,
        public bool $frontchannelLogout,
        public string $protocol,
        public array $attributes,
        public array $authenticationFlowBindingOverrides,
        public bool $fullScopeAllowed,
        public int $nodeReRegistrationTimeout,
        public array $protocolMappers,
        public array $defaultClientScopes,
        public array $optionalClientScopes,
        public array $access
    ) {
    }

    public static function fromArray(array $data): self
    {
        return new self(
            id: $data['id'],
            clientId: $data['clientId'],
            name: $data['name'],
            description: $data['description'],
            rootUrl: $data['rootUrl'],
            adminUrl: $data['adminUrl'],
            baseUrl: $data['baseUrl'],
            surrogateAuthRequired: $data['surrogateAuthRequired'],
            enabled: $data['enabled'],
            alwaysDisplayInConsole: $data['alwaysDisplayInConsole'],
            clientAuthenticatorType: $data['clientAuthenticatorType'],
            secret: $data['secret'],
            redirectUris: $data['redirectUris'],
            webOrigins: $data['webOrigins'],
            notBefore: $data['notBefore'],
            bearerOnly: $data['bearerOnly'],
            consentRequired: $data['consentRequired'],
            standardFlowEnabled: $data['standardFlowEnabled'],
            implicitFlowEnabled: $data['implicitFlowEnabled'],
            directAccessGrantsEnabled: $data['directAccessGrantsEnabled'],
            serviceAccountsEnabled: $data['serviceAccountsEnabled'],
            authorizationServicesEnabled: $data['authorizationServicesEnabled'],
            publicClient: $data['publicClient'],
            frontchannelLogout: $data['frontchannelLogout'],
            protocol: $data['protocol'],
            attributes: $data['attributes'],
            authenticationFlowBindingOverrides: $data['authenticationFlowBindingOverrides'],
            fullScopeAllowed: $data['fullScopeAllowed'],
            nodeReRegistrationTimeout: $data['nodeReRegistrationTimeout'],
            protocolMappers: $data['protocolMappers'],
            defaultClientScopes: $data['defaultClientScopes'],
            optionalClientScopes: $data['optionalClientScopes'],
            access: $data['access']
        );
    }
}
