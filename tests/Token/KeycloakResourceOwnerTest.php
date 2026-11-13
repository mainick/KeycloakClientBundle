<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Token;

use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use PHPUnit\Framework\TestCase;

class KeycloakResourceOwnerTest extends TestCase
{
    public function testGetAttributesReturnsTheAttributesClaim(): void
    {
        $owner = new KeycloakResourceOwner(['attributes' => ['agency_id' => 'a-1', 'locale' => 'it']]);

        $this->assertSame(['agency_id' => 'a-1', 'locale' => 'it'], $owner->getAttributes());
    }

    public function testGetAttributesReturnsAnEmptyArrayWithoutTheClaim(): void
    {
        $owner = new KeycloakResourceOwner(['sub' => 'user-1']);

        $this->assertSame([], $owner->getAttributes());
    }

    public function testGetAttributeReturnsTheValueOrNull(): void
    {
        $owner = new KeycloakResourceOwner(['attributes' => ['agency_id' => 'a-1']]);

        $this->assertSame('a-1', $owner->getAttribute('agency_id'));
        $this->assertNull($owner->getAttribute('missing'));
    }
}
