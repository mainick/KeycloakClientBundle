<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

enum UnmanagedAttributePolicyEnum: string
{
    case ENABLED = 'ENABLED';
    case ADMIN_VIEW = 'ADMIN_VIEW';
    case ADMIN_EDIT = 'ADMIN_EDIT';
}
