<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('mainick_keycloak_client');
        $rootNode = $treeBuilder->getRootNode();
        $adminCliChildren = $rootNode->children()->arrayNode('admin_cli')->children();

        $rootNode
            ->children()
                ->arrayNode('keycloak')
                    ->children()
                        ->booleanNode('verify_ssl')->isRequired()->defaultTrue()->end()
                        ->scalarNode('base_url')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('realm')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('client_id')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('client_secret')->defaultNull()->end()
                        ->scalarNode('redirect_uri')->defaultNull()->end()
                        ->scalarNode('encryption_algorithm')->defaultNull()->end()
                        ->scalarNode('encryption_key')->defaultNull()->end()
                        ->scalarNode('encryption_key_path')->defaultNull()->end()
                        ->scalarNode('version')->defaultNull()->end()
                    ->end()
                ->end()
                ->arrayNode('security')
                    ->info('Enable this if you want to use the Keycloak security layer. This will protect your application with Keycloak.')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('default_target_route_name')->defaultNull()->end()
                    ->end()
                ->end()
                ->arrayNode('admin_cli')
                    ->info('Enable this if you want to use the admin-cli client to authenticate with Keycloak. This is useful if you want to use the Keycloak Admin REST API.')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('client_id')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('username')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('password')->isRequired()->cannotBeEmpty()->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
