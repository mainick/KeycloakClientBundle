<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Interface;

use Mainick\KeycloakClientBundle\Service\ClientsService;
use Mainick\KeycloakClientBundle\Service\GroupsService;
use Mainick\KeycloakClientBundle\Service\RealmsService;
use Mainick\KeycloakClientBundle\Service\RolesService;
use Mainick\KeycloakClientBundle\Service\UsersService;

interface IamAdminClientInterface
{
    public function getBaseUrl(): string;

    public function getRealm(): string;

    public function getClientId(): string;

    public function realms(): RealmsService;

    public function clients(): ClientsService;

    public function users(): UsersService;

    public function groups(): GroupsService;

    public function roles(): RolesService;
}
