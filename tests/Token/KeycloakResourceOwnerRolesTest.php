<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Token;

use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use Mainick\KeycloakClientBundle\Token\RolesSourceEnum;
use PHPUnit\Framework\TestCase;

class KeycloakResourceOwnerRolesTest extends TestCase
{
    private const CLIENT_ROLES = ['business-app' => ['ROLE_AREA_AGENCY']];

    /**
     * @param array<string,mixed> $extra
     *
     * @return array<string,mixed>
     */
    private function claims(array $extra = []): array
    {
        return [
            'sub' => 'user-1',
            'azp' => 'business-app',
            'realm_access' => ['roles' => ['ROLE_REALM']],
            'resource_access' => [
                'business-app' => ['roles' => ['ROLE_AGENCY_BOOKINGS']],
                'admin-app' => ['roles' => ['ROLE_ADMIN']],
            ],
            ...$extra,
        ];
    }

    public function testDefaultSourceKeepsTheRolesOfVersion41AndIgnoresClientRoles(): void
    {
        $owner = new KeycloakResourceOwner($this->claims(), clientRoles: self::CLIENT_ROLES);

        $this->assertSame(['ROLE_REALM', 'ROLE_AGENCY_BOOKINGS', 'ROLE_ADMIN'], $owner->getRoles());
    }

    public function testAuthorizedPartySourceKeepsOnlyTheTokenClientRolesPlusItsClientRoles(): void
    {
        $owner = new KeycloakResourceOwner($this->claims(), null, RolesSourceEnum::AUTHORIZED_PARTY, self::CLIENT_ROLES);

        $this->assertSame(['ROLE_AGENCY_BOOKINGS', 'ROLE_AREA_AGENCY'], $owner->getRoles());
    }

    public function testAnExplicitClientIdReturnsRealmAndThatClientRolesWhateverTheSource(): void
    {
        $owner = new KeycloakResourceOwner($this->claims(), null, RolesSourceEnum::AUTHORIZED_PARTY, self::CLIENT_ROLES);

        $this->assertSame(['ROLE_REALM', 'ROLE_ADMIN'], $owner->getRoles('admin-app'));
    }

    public function testAuthorizedPartySourceWithoutAzpHasNoRoles(): void
    {
        $claims = $this->claims();
        unset($claims['azp']);
        $owner = new KeycloakResourceOwner($claims, null, RolesSourceEnum::AUTHORIZED_PARTY, self::CLIENT_ROLES);

        $this->assertSame([], $owner->getRoles());
    }

    public function testMalformedRolesClaimIsIgnored(): void
    {
        $owner = new KeycloakResourceOwner(
            $this->claims(['resource_access' => ['business-app' => ['roles' => 'ROLE_AGENCY_BOOKINGS']]]),
            null,
            RolesSourceEnum::AUTHORIZED_PARTY,
        );

        $this->assertSame([], $owner->getRoles());
    }
}
