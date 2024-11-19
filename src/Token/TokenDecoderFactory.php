<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use JetBrains\PhpStorm\Pure;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;

class TokenDecoderFactory
{
    #[Pure]
    public static function create($algorithm): TokenDecoderInterface
    {
        return match ($algorithm) {
            'RS256' => new RS256TokenDecoder(),
            'HS256' => new HS256TokenDecoder(),
            default => throw new \RuntimeException('Invalid algorithm'),
        };
    }
}
