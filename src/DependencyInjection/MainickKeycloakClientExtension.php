<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DependencyInjection;

use Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakBearerAuthenticator;
use Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakOptionalBearerAuthenticator;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;

class MainickKeycloakClientExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader(
            $container,
            new FileLocator(dirname(__DIR__).'/Resources/config')
        );
        $loader->load('services.yaml');

        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        foreach ($config['keycloak'] as $key => $value) {
            $container->setParameter('mainick_keycloak_client.keycloak.'.$key, $value);
        }
        foreach ($config['security'] as $key => $value) {
            $container->setParameter('mainick_keycloak_client.security.'.$key, $value);
        }
        foreach ($config['bearer'] as $key => $value) {
            $container->setParameter('mainick_keycloak_client.bearer.'.$key, $value);
        }
        if (!$config['bearer']['enabled']) {
            $container->removeDefinition(KeycloakBearerAuthenticator::class);
            $container->removeDefinition(KeycloakOptionalBearerAuthenticator::class);
        }
        foreach ($config['admin_cli'] as $key => $value) {
            if ('enabled' === $key) {
                continue;
            }
            $container->setParameter('mainick_keycloak_client.admin_cli.'.$key, $value);
        }
    }
}
