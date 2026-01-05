<?php
declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Mainick\KeycloakClientBundle\Exception\TokenDecoderException;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;

final class JWKSTokenDecoder implements TokenDecoderInterface
{
    private array $jwksCache = [];
    private int $cacheTtl = 300; // 5 minutes
    private ?int $lastFetch = null;

    public function __construct(private readonly array $options)
    {
        foreach (['base_url', 'realm'] as $requiredOption) {
            if (!\array_key_exists($requiredOption, $this->options) || $this->options[$requiredOption] === null || $this->options[$requiredOption] === '') {
                throw new \InvalidArgumentException(\sprintf(
                    "Missing or empty required option '%s' for %s",
                    $requiredOption,
                    self::class
                ));
            }
        }
    }

    /**
     * Decode a JWT using keys resolved dynamically from JWKS.
     *
     * The {@see TokenDecoderInterface} requires a $key parameter, but this
     * JWKS-based implementation does not use it because the verification key
     * is selected based on the "kid" value in the token header and fetched
     * from the JWKS endpoint. Callers may pass an empty string or any
     * placeholder value for $key when using this decoder.
     *
     * @param string $token The encoded JWT to decode.
     * @param string $key   Unused in this JWKS-based implementation; present
     *                      only to satisfy the TokenDecoderInterface.
     *
     * @throws TokenDecoderException
     */
    public function decode(string $token, string $key): array
    {
        try {
            [$headerB64] = explode('.', $token, 2);
            $header = json_decode($this->base64urlDecode($headerB64), true);
            $kid = $header['kid'] ?? throw new \RuntimeException('Missing kid in JWT header');
            $alg = $header['alg'] ?? 'RS256';

            $keyPem = $this->getPemKeyForKid($kid);
            $tokenDecoded = JWT::decode($token, new Key($keyPem, $alg));

            $json = json_encode($tokenDecoded, JSON_THROW_ON_ERROR);

            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\Throwable $e) {
            throw new TokenDecoderException('Failed to decode token', 0, $e);
        }
    }

    /**
     * @throws TokenDecoderException
     */
    public function validateToken(string $realm, array $tokenDecoded): void
    {
        $now = time();

        if ($tokenDecoded['exp'] < $now) {
            throw TokenDecoderException::forExpiration(new \Exception('Token has expired'));
        }

        if (false === str_contains($tokenDecoded['iss'], $realm)) {
            throw TokenDecoderException::forIssuerMismatch(new \Exception('Invalid token issuer'));
        }
    }

    private function getPemKeyForKid(string $kid): string
    {
        // Simple cache
        if (!$this->jwksCache || !$this->lastFetch || (time() - $this->lastFetch > $this->cacheTtl)) {
            $this->jwksCache = $this->fetchJwks();
            $this->lastFetch = time();
        }

        foreach ($this->jwksCache as $jwk) {
            if (($jwk['kid'] ?? '') === $kid && ($jwk['use'] ?? '') === 'sig') {
                return $this->jwkToPem($jwk);
            }
        }

        throw new \RuntimeException("No matching JWK found for kid: $kid");
    }

    private function fetchJwks(): array
    {
        $url = sprintf('%s/realms/%s/protocol/openid-connect/certs', $this->options['base_url'], $this->options['realm']);
        $json = @file_get_contents($url);
        if (!$json) {
            throw new \RuntimeException("Failed to fetch JWKS from $url");
        }

        $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

        return $data['keys'] ?? [];
    }

    private function jwkToPem(array $jwk): string
    {
        if (!empty($jwk['x5c'][0])) {
            $pemCert = "-----BEGIN CERTIFICATE-----\n".
                chunk_split($jwk['x5c'][0], 64, "\n").
                "-----END CERTIFICATE-----\n";
            $key = openssl_pkey_get_public($pemCert);
            if ($key === false) {
                throw new \RuntimeException('Failed to get public key from certificate using OpenSSL');
            }
            $details = openssl_pkey_get_details($key);
            if ($details === false || !isset($details['key'])) {
                throw new \RuntimeException('Failed to get public key details from certificate using OpenSSL');
            }

            return $details['key']; // This is the PEM public key
        }

        if (!isset($jwk['n'], $jwk['e'])) {
            throw new \RuntimeException('JWK missing modulus or exponent');
        }

        $modulus = $this->base64urlDecode($jwk['n']);
        $exponent = $this->base64urlDecode($jwk['e']);

        $modulusEnc = $this->encodeAsn1Integer($modulus);
        $exponentEnc = $this->encodeAsn1Integer($exponent);
        $seq = $this->encodeAsn1Sequence($modulusEnc.$exponentEnc);

        $algo = hex2bin('300d06092a864886f70d0101010500'); // rsaEncryption OID
        $bitStr = "\x03".chr(strlen($seq) + 1)."\x00".$seq;
        $spki = $this->encodeAsn1Sequence($algo.$bitStr);

        return "-----BEGIN PUBLIC KEY-----\n"
            .chunk_split(base64_encode($spki), 64, "\n")
            ."-----END PUBLIC KEY-----\n";
    }

    private function base64urlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new \RuntimeException('Invalid base64url-encoded data.');
        }

        return $decoded;
    }

    private function encodeAsn1Integer(string $bytes): string
    {
        if (ord($bytes[0]) > 0x7F) {
            $bytes = "\x00".$bytes;
        }

        return "\x02".$this->encodeLength(strlen($bytes)).$bytes;
    }

    private function encodeAsn1Sequence(string $bytes): string
    {
        return "\x30".$this->encodeLength(strlen($bytes)).$bytes;
    }

    private function encodeLength(int $len): string
    {
        if ($len < 128) {
            return chr($len);
        }
        $tmp = ltrim(pack('N', $len), "\x00");

        return chr(0x80 | strlen($tmp)).$tmp;
    }
}
