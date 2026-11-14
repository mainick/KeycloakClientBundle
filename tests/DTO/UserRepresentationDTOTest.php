<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\DTO;

use Mainick\KeycloakClientBundle\DTO\OrganizationRepresentationDTO;
use Mainick\KeycloakClientBundle\DTO\RoleRepresentationDTO;
use Mainick\KeycloakClientBundle\DTO\UserRepresentationDTO;
use PHPUnit\Framework\TestCase;

class UserRepresentationDTOTest extends TestCase
{
    /**
     * @param array<string,mixed> $extra
     *
     * @return array<string,mixed>
     */
    private function claims(array $extra = []): array
    {
        return [
            'sub' => 'user-1',
            'preferred_username' => 'mario',
            'email_verified' => true,
            'email' => 'mario@example.test',
            ...$extra,
        ];
    }

    public function testPictureComesFromTheStandardClaim(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims([
            'picture' => 'https://example.test/a.png',
            'attributes' => ['picture' => 'https://example.test/b.png'],
        ]));

        $this->assertSame('https://example.test/a.png', $dto->picture);
    }

    public function testPictureFallsBackToTheUserAttribute(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims([
            'attributes' => ['picture' => 'https://example.test/b.png'],
        ]));

        $this->assertSame('https://example.test/b.png', $dto->picture);
    }

    public function testPictureIsNullWhenMissing(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims());

        $this->assertNull($dto->picture);
    }

    public function testAuthorizedPartyAndItsRolesComeFromAzpAndResourceAccess(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims([
            'azp' => 'business-app',
            'resource_access' => [
                'business-app' => ['roles' => ['ROLE_AGENCY_BOOKINGS']],
                'admin-app' => ['roles' => ['ROLE_ADMIN']],
            ],
        ]));

        $this->assertSame('business-app', $dto->authorizedParty);
        $this->assertSame(
            ['ROLE_AGENCY_BOOKINGS'],
            array_map(static fn (RoleRepresentationDTO $role): string => $role->name, $dto->authorizedPartyRoles ?? []),
        );
    }

    public function testAuthorizedPartyFieldsAreNullWithoutAzp(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims([
            'resource_access' => ['admin-app' => ['roles' => ['ROLE_ADMIN']]],
        ]));

        $this->assertNull($dto->authorizedParty);
        $this->assertNull($dto->authorizedPartyRoles);
    }

    public function testOrganizationsFromTheDefaultAliasList(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims([
            'organization' => ['acme', 'globex'],
        ]));

        $this->assertEquals(
            [new OrganizationRepresentationDTO('acme'), new OrganizationRepresentationDTO('globex')],
            $dto->organizations,
        );
    }

    public function testOrganizationsFromASingleAliasString(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims([
            'organization' => 'acme',
        ]));

        $this->assertEquals([new OrganizationRepresentationDTO('acme')], $dto->organizations);
    }

    public function testOrganizationsFromTheMapWithIdAndAttributes(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims([
            'organization' => [
                'acme' => ['id' => 'org-1', 'country' => ['IT']],
                'globex' => [],
            ],
        ]));

        $this->assertEquals(
            [
                new OrganizationRepresentationDTO('acme', 'org-1', ['country' => ['IT']]),
                new OrganizationRepresentationDTO('globex'),
            ],
            $dto->organizations,
        );
    }

    public function testOrganizationsAreNullWithoutTheClaim(): void
    {
        $dto = UserRepresentationDTO::fromArray($this->claims());

        $this->assertNull($dto->organizations);
    }

    public function testIssuerExpirationAndRawClaims(): void
    {
        $claims = $this->claims([
            'iss' => 'https://sso.example.test/realms/demo',
            'exp' => 1893456000,
            'custom' => 'value',
        ]);

        $dto = UserRepresentationDTO::fromArray($claims);

        $this->assertSame('https://sso.example.test/realms/demo', $dto->issuer);
        $this->assertSame(1893456000, $dto->expiresAt);
        $this->assertSame($claims, $dto->claims);
    }

    public function testPositionalConstructorOfVersion41StillWorks(): void
    {
        $dto = new UserRepresentationDTO(
            'user-1',
            'mario',
            true,
            null,
            null,
            null,
            'mario@example.test',
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            'https://example.test/a.png',
        );

        $this->assertSame('https://example.test/a.png', $dto->picture);
        $this->assertNull($dto->authorizedParty);
        $this->assertNull($dto->organizations);
        $this->assertNull($dto->claims);
    }
}
