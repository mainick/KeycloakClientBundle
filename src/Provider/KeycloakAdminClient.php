<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Provider;

use GuzzleHttp\Client;
use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Interface\IamAdminClientInterface;
use Mainick\KeycloakClientBundle\Service\ClientsService;
use Mainick\KeycloakClientBundle\Service\GroupsService;
use Mainick\KeycloakClientBundle\Service\RealmsService;
use Mainick\KeycloakClientBundle\Service\RolesService;
use Mainick\KeycloakClientBundle\Service\UsersService;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class KeycloakAdminClient implements IamAdminClientInterface
{
    private Keycloak $keycloakProvider;
    private ?AccessTokenInterface $adminAccessToken = null;

    public function __construct(
        private readonly LoggerInterface $keycloakClientLogger,
        private readonly bool $verify_ssl,
        private readonly string $base_url,
        private readonly string $admin_realm,
        private readonly string $admin_client_id,
        private readonly string $admin_username,
        private readonly string $admin_password,
        private readonly string $version = '',
    ) {
        $this->keycloakProvider = new Keycloak([
            'authServerUrl' => $this->base_url,
            'realm' => $this->admin_realm,
            'clientId' => $this->admin_client_id,
        ]);

        if ('' !== $this->version) {
            $this->keycloakProvider->setVersion($this->version);
        }

        $httpClient = new Client([
            'verify' => $this->verify_ssl,
        ]);
        $this->keycloakProvider->setHttpClient($httpClient);
    }

    public function getKeycloakProvider(): Keycloak
    {
        return $this->keycloakProvider;
    }

    public function getBaseUrl(): string
    {
        return $this->base_url;
    }

    public function getRealm(): string
    {
        return $this->admin_realm;
    }

    public function getClientId(): string
    {
        return $this->admin_client_id;
    }

    public function getUsername(): string
    {
        return $this->admin_username;
    }

    public function getPassword(): string
    {
        return $this->admin_password;
    }

    public function getVersion(): string
    {
        return $this->version;
    }

    public function getAdminAccessToken(): ?AccessTokenInterface
    {
        return $this->adminAccessToken;
    }

    public function setAdminAccessToken(AccessTokenInterface $adminAccessToken): void
    {
        $this->adminAccessToken = $adminAccessToken;
    }

    public function realms(): RealmsService
    {
        return new RealmsService($this->keycloakClientLogger, $this);
    }

    public function clients(): ClientsService
    {
        return new ClientsService($this->keycloakClientLogger, $this);
    }

    public function users(): UsersService
    {
        return new UsersService($this->keycloakClientLogger, $this);
    }

    public function groups(): GroupsService
    {
        return new GroupsService($this->keycloakClientLogger, $this);
    }

    public function roles(): RolesService
    {
        return new RolesService($this->keycloakClientLogger, $this);
    }
}
