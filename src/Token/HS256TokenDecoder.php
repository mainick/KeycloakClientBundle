<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Mainick\KeycloakClientBundle\Exception\TokenDecoderException;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;

class HS256TokenDecoder implements TokenDecoderInterface
{

    public function decode(string $token, string $key): array
    {
        try {
            $tokenDecoded = JWT::decode($token, new Key($key, 'HS256'));

            $json = json_encode($tokenDecoded, JSON_THROW_ON_ERROR);

            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Exception $e) {
            throw new TokenDecoderException('Error decoding token', $e);
        }
    }

    public function validateToken(string $realm, array $tokenDecoded): void
    {
        $now = time();

        if ($tokenDecoded['exp'] < $now) {
            throw TokenDecoderException::forExpiration(new \Exception('Token has expired'));
        }

        if (str_contains($tokenDecoded['iss'], $realm) === false) {
            throw TokenDecoderException::forIssuerMismatch(new \Exception('Invalid token issuer'));
        }
//
//        if ($tokenDecoded['aud'] !== 'account') {
//            throw TokenDecoderException::forAudienceMismatch(new \Exception('Invalid token audience'));
//        }
    }
}
