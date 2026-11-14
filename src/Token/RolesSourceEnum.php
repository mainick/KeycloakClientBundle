<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

/**
 * Where {@see KeycloakResourceOwner::getRoles()} takes the roles from.
 */
enum RolesSourceEnum: string
{
    /** Realm roles plus the roles of every client, as KeycloakResourceOwner always did. */
    case ALL = 'all';

    /** Only the roles of the client that requested the token (`azp`), plus the configured client roles. */
    case AUTHORIZED_PARTY = 'authorized_party';
}
