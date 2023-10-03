<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Mainick\KeycloakClientBundle\Exception\TokenDecoderException;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;

class HS256TokenDecoder implements TokenDecoderInterface
{
    public function decode(string $token, string $key): array
    {
        // https://github.com/firebase/php-jwt#example-encodedecode-headers
        [$headersB64, $payloadB64, $sig] = explode('.', $token);
        $tokenDecoded = json_decode(base64_decode($payloadB64), true, 512, JSON_THROW_ON_ERROR);

        try {
            $json = json_encode($tokenDecoded, JSON_THROW_ON_ERROR);

            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        }
        catch (\Exception $e) {
            throw new TokenDecoderException('Error decoding token', $e);
        }
    }
}
