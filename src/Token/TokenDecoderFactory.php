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
        switch ($algorithm) {
            case 'RS256':
                return new RS256TokenDecoder();
            case 'HS256':
                return new HS256TokenDecoder();
            default:
                throw new \RuntimeException('Invalid algorithm');
        }
    }
}
