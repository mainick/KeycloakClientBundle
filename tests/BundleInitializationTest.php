<?php

declare(strict_types=1);

use Mainick\KeycloakClientBundle\MainickKeycloakClientBundle;
use Nyholm\BundleTest\TestKernel;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpKernel\KernelInterface;

class BundleInitializationTest extends KernelTestCase
{
    protected static function getKernelClass(): string
    {
        return TestKernel::class;
    }

    protected static function createKernel(array $options = []): KernelInterface
    {
        /** @var TestKernel $kernel */
        $kernel = parent::createKernel($options);
        $kernel->addTestBundle(MainickKeycloakClientBundle::class);
        $kernel->handleOptions($options);

        return $kernel;
    }

    public function testInitBundle(): void
    {
        //$kernel = static::bootKernel();
        //$container = $kernel->getContainer();
        $container = self::getContainer();

        // test if your services exists
        $this->assertTrue($container->has('mainick.keycloak_client_bundle.client'));
        $service = $container->get('mainick.keycloak_client_bundle.client');
    }
}
