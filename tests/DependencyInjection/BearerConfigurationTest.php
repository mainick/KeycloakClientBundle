<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\DependencyInjection;

use Mainick\KeycloakClientBundle\DependencyInjection\Configuration;
use Mainick\KeycloakClientBundle\DependencyInjection\MainickKeycloakClientExtension;
use Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakBearerAuthenticator;
use Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakOptionalBearerAuthenticator;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\ContainerBuilder;

class BearerConfigurationTest extends TestCase
{
    /**
     * @param array<string,mixed> $extra
     *
     * @return array<string,mixed>
     */
    private function config(array $extra = []): array
    {
        return [
            'keycloak' => [
                'base_url' => 'http://keycloak.internal:8080',
                'realm' => 'demo',
                'client_id' => 'api',
                'encryption_algorithm' => 'RS256',
                'encryption_key' => 'abc',
            ],
            ...$extra,
        ];
    }

    /**
     * @param array<string,mixed> $config
     *
     * @return array<string,mixed>
     */
    private function process(array $config): array
    {
        return (new Processor())->processConfiguration(new Configuration(), [$config]);
    }

    public function testBearerIsDisabledByDefaultAndKeepsTodaysRoles(): void
    {
        $processed = $this->process($this->config());

        $this->assertFalse($processed['bearer']['enabled']);
        $this->assertSame('all', $processed['bearer']['roles_source']);
        $this->assertSame([], $processed['bearer']['allowed_clients']);
        $this->assertSame([], $processed['bearer']['client_roles']);
        $this->assertNull($processed['keycloak']['issuer']);
    }

    public function testClientIdsWithDashesAreKeptAsKeys(): void
    {
        $processed = $this->process($this->config(['bearer' => [
            'enabled' => true,
            'roles_source' => 'authorized_party',
            'allowed_clients' => ['consumer-app', 'business-app'],
            'client_roles' => ['business-app' => ['ROLE_AREA_AGENCY']],
        ]]));

        $this->assertSame(['business-app' => ['ROLE_AREA_AGENCY']], $processed['bearer']['client_roles']);
        $this->assertSame(['consumer-app', 'business-app'], $processed['bearer']['allowed_clients']);
    }

    public function testUnknownRolesSourceIsInvalid(): void
    {
        $this->expectException(InvalidConfigurationException::class);

        $this->process($this->config(['bearer' => ['enabled' => true, 'roles_source' => 'realm']]));
    }

    public function testAuthenticatorsAreRegisteredOnlyWhenBearerIsEnabled(): void
    {
        $disabled = new ContainerBuilder();
        (new MainickKeycloakClientExtension())->load([$this->config()], $disabled);
        $this->assertFalse($disabled->hasDefinition(KeycloakBearerAuthenticator::class));
        $this->assertFalse($disabled->hasDefinition(KeycloakOptionalBearerAuthenticator::class));

        $enabled = new ContainerBuilder();
        (new MainickKeycloakClientExtension())->load([$this->config(['bearer' => ['enabled' => true]])], $enabled);
        $this->assertTrue($enabled->hasDefinition(KeycloakBearerAuthenticator::class));
        $this->assertTrue($enabled->hasDefinition(KeycloakOptionalBearerAuthenticator::class));
        $this->assertSame('all', $enabled->getParameter('mainick_keycloak_client.bearer.roles_source'));
    }
}
