<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\DTO;

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
}
