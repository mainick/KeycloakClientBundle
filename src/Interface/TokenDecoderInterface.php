<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Interface;

interface TokenDecoderInterface
{
    /**
     * @return array<string, mixed>
     */
    public function decode(string $token, string $key): array;

    /**
     * @param string $realm
     * @param array<string, mixed> $tokenDecoded
     */
    public function validateToken(string $realm, array $tokenDecoded): void;
}
