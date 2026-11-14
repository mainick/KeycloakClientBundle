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
                        ->booleanNode('verify_ssl')->defaultTrue()->end()
                        ->scalarNode('base_url')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('realm')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('client_id')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('client_secret')->defaultNull()->end()
                        ->scalarNode('redirect_uri')->defaultNull()->end()
                        ->scalarNode('encryption_algorithm')->defaultNull()->end()
                        ->scalarNode('encryption_key')->defaultNull()->end()
                        ->scalarNode('encryption_key_path')->defaultNull()->end()
                        ->scalarNode('encryption_key_passphrase')->defaultNull()->end()
                        ->scalarNode('version')->defaultNull()->end()
                        ->scalarNode('issuer')
                            ->info('Expected "iss" claim of the tokens, e.g. "https://sso.example.com/realms/my-realm". When set, it must match exactly; when null, the issuer only has to contain the realm name. Set it when the application reaches Keycloak on a different URL than the one that issues the tokens.')
                            ->defaultNull()
                        ->end()
                        ->arrayNode('allowed_jwks_domains')
                            ->info('Whitelist of allowed domains for JWKS endpoint requests. If empty, only the base_url domain is allowed.')
                            ->scalarPrototype()->end()
                        ->end()
                    ->end()
                    ->validate()
                        ->ifTrue(function ($v) {
                            return empty($v['encryption_key']) && empty($v['encryption_key_path']);
                        })
                        ->thenInvalid('At least one of "encryption_key" or "encryption_key_path" must be provided.')
                    ->end()
                ->end()
                ->arrayNode('security')
                    ->info('Enable this if you want to use the Keycloak security layer. This will protect your application with Keycloak.')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('default_target_route_name')->defaultNull()->end()
                    ->end()
                ->end()
                ->arrayNode('bearer')
                    ->info('Enable this to protect APIs with a stateless "Authorization: Bearer" authenticator that verifies the access token locally.')
                    ->canBeEnabled()
                    ->children()
                        ->enumNode('roles_source')
                            ->info('"all": realm roles and the roles of every client (as KeycloakResourceOwner always did); "authorized_party": only the roles of the client that requested the token (azp).')
                            ->values(['all', 'authorized_party'])
                            ->defaultValue('all')
                        ->end()
                        ->arrayNode('allowed_clients')
                            ->info('Clients (azp) whose tokens are accepted. Empty means any client of the realm.')
                            ->scalarPrototype()->end()
                        ->end()
                        ->arrayNode('client_roles')
                            ->info('Extra roles granted according to the client that requested the token, e.g. { consumer-app: [ROLE_CUSTOMER] }.')
                            ->useAttributeAsKey('client')
                            ->normalizeKeys(false)
                            ->arrayPrototype()
                                ->scalarPrototype()->end()
                            ->end()
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('admin_cli')
                    ->info('Enable this if you want to use the admin-cli client to authenticate with Keycloak. This is useful if you want to use the Keycloak Admin REST API.')
                    ->canBeEnabled()
                    ->children()
                        ->scalarNode('realm')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('client_id')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('username')->isRequired()->cannotBeEmpty()->end()
                        ->scalarNode('password')->isRequired()->cannotBeEmpty()->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
