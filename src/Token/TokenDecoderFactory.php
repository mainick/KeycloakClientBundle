<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use JetBrains\PhpStorm\Pure;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;

class TokenDecoderFactory
{
    public const ALGORITHM_RS256 = 'RS256';
    public const ALGORITHM_HS256 = 'HS256';
    public const ALGORITHM_JWKS = 'JWKS';

	#[Pure]
	public static function create($algorithm, array $options = []): TokenDecoderInterface
	{
		return match ($algorithm) {
			self::ALGORITHM_RS256 => new RS256TokenDecoder(),
			self::ALGORITHM_HS256 => new HS256TokenDecoder(),
			self::ALGORITHM_JWKS => new JWKSTokenDecoder($options),
			default => throw new \RuntimeException('Invalid algorithm'),
		};
	}
}
