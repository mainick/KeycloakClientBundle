<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Mainick\KeycloakClientBundle\Exception\TokenDecoderException;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;
use Psr\Log\LoggerInterface;

class HS256TokenDecoder implements TokenDecoderInterface
{
    private LoggerInterface $logger;

    public function __construct(LoggerInterface $logger)
    {
        $this->logger = $logger;
    }

    public function decode(string $token, string $key): array
    {
        try {
            $decoded = JWT::decode($token, new Key($key, 'HS256'));

            $this->validateToken($decoded);

            return (array) $decoded;
        } catch (\Exception $e) {
            $this->logger->error('Error decoding token', ['exception' => $e]);
            throw new TokenDecoderException('Error decoding token', $e);
        }
    }

    private function validateToken($token): void
    {
        $now = time();

        if ($token->exp < $now) {
            $this->logger->error('Token has expired', ['exp' => $token->exp, 'now' => $now]);
            throw new TokenDecoderException('Token has expired');
        }

        if ($token->iss !== 'trusted-issuer') {
            $this->logger->error('Invalid token issuer', ['iss' => $token->iss]);
            throw new TokenDecoderException('Invalid token issuer');
        }

        if ($token->aud !== 'your-audience') {
            $this->logger->error('Invalid token audience', ['aud' => $token->aud]);
            throw new TokenDecoderException('Invalid token audience');
        }
    }
}
