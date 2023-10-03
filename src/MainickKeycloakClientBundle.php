<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle;

use Mainick\KeycloakClientBundle\DependencyInjection\MainickKeycloakClientExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class MainickKeycloakClientBundle extends AbstractBundle
{
    public function getPath(): string
    {
        return dirname(__DIR__);
    }

    public function getContainerExtension(): ?ExtensionInterface
    {
        return new MainickKeycloakClientExtension();
    }
}
