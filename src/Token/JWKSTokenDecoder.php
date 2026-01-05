<?php
declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Mainick\KeycloakClientBundle\Exception\TokenDecoderException;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;

final class JWKSTokenDecoder implements TokenDecoderInterface
{

    public function __construct(
        private readonly array $options,
        private readonly ?ClientInterface $httpClient = null
    )
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

        // Validate base_url format
        $this->validateBaseUrl($this->options['base_url']);
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
            $header = json_decode($this->base64urlDecode($headerB64), true, 512, JSON_THROW_ON_ERROR);

            $kid = $header['kid'] ?? '';
            $alg = $header['alg'] ?? '';

            $keyPem = $this->getPemKeyForKid($kid);
            $tokenDecoded = JWT::decode($token, new Key($keyPem, $alg));

            $json = json_encode($tokenDecoded, JSON_THROW_ON_ERROR);

            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        }
        catch (\Exception $e) {
            throw new TokenDecoderException('Error decoding token', $e);
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
        $jwks = $this->fetchJwks();
        if (empty($jwks)) {
            throw TokenDecoderException::forInvalidToken(new \Exception('No JWKs found from JWKS endpoint'));
        }
        foreach ($jwks as $jwk) {
            if (($jwk['kid'] ?? '') === $kid && ($jwk['use'] ?? '') === 'sig') {
                return $this->jwkToPem($jwk);
            }
        }

        throw TokenDecoderException::forInvalidToken(new \Exception("No matching JWK found for kid: $kid"));
    }

    private function fetchJwks(): array
    {
        $url = sprintf('%s/realms/%s/protocol/openid-connect/certs', $this->options['base_url'], $this->options['realm']);

        // Validate the constructed JWKS URL
        $this->validateJwksUrl($url);

        try {
            if ($this->httpClient !== null) {
                $response = $this->httpClient->request('GET', $url, [
                    'timeout' => 10,
                    'connect_timeout' => 5,
                ]);
                $json = $response->getBody()->getContents();
            } else {
                // Fallback to file_get_contents if no HTTP client provided
                $context = stream_context_create([
                    'http' => [
                        'timeout' => 10,
                    ],
                ]);
                $json = file_get_contents($url, false, $context);
                if ($json === false) {
                    throw new \RuntimeException('Unable to fetch JWKS from cert endpoint');
                }
            }

            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

            return $data['keys'] ?? [];
        } catch (GuzzleException $e) {
            throw TokenDecoderException::forInvalidToken(new \Exception('Failed to fetch JWKS: ' . $e->getMessage(), 0, $e));
        } catch (\Exception $e) {
            throw TokenDecoderException::forInvalidToken(new \Exception('Unable to open cert file: ' . $e->getMessage(), 0, $e));
        }
    }

    private function jwkToPem(array $jwk): string
    {
        if (!empty($jwk['x5c'][0])) {
            $pemCert = "-----BEGIN CERTIFICATE-----\n".
                chunk_split($jwk['x5c'][0], 64, "\n").
                "-----END CERTIFICATE-----\n";
            $key = openssl_pkey_get_public($pemCert);
            if ($key === false) {
                throw TokenDecoderException::forInvalidToken(new \Exception('Failed to get public key from certificate using OpenSSL'));
            }
            $details = openssl_pkey_get_details($key);
            if ($details === false || !isset($details['key'])) {
                throw TokenDecoderException::forInvalidToken(new \Exception('Failed to get public key details from certificate using OpenSSL'));
            }

            return $details['key']; // This is the PEM public key
        }

        if (!isset($jwk['n'], $jwk['e'])) {
            throw TokenDecoderException::forInvalidToken(new \Exception('JWK missing modulus or exponent'));
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
            throw TokenDecoderException::forInvalidToken(new \Exception('Failed to decode token'));
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

    /**
     * Validate the base URL format to prevent SSRF attacks.
     *
     * @throws \InvalidArgumentException
     */
    private function validateBaseUrl(string $baseUrl): void
    {
        // Parse the URL
        $parsed = parse_url($baseUrl);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid base_url format: %s. Expected a valid URL with scheme and host.',
                $baseUrl
            ));
        }

        // Only allow HTTPS (or HTTP for localhost/development)
        if (!in_array($parsed['scheme'], ['https', 'http'], true)) {
            throw new \InvalidArgumentException(sprintf(
                'Invalid base_url scheme: %s. Only http and https are allowed.',
                $parsed['scheme']
            ));
        }

        // Enforce HTTPS for non-localhost environments
        if ($parsed['scheme'] === 'http' && !$this->isLocalhost($parsed['host'])) {
            throw new \InvalidArgumentException(sprintf(
                'HTTP is only allowed for localhost. Use HTTPS for: %s',
                $parsed['host']
            ));
        }

        // Prevent private IP ranges and localhost in production unless explicitly localhost
        if (!$this->isAllowedHost($parsed['host'])) {
            throw new \InvalidArgumentException(sprintf(
                'The host %s is not allowed. Private IPs and internal hosts are blocked for security.',
                $parsed['host']
            ));
        }
    }

    /**
     * Validate the JWKS URL against a whitelist of allowed domains.
     *
     * @throws TokenDecoderException
     */
    private function validateJwksUrl(string $url): void
    {
        $parsed = parse_url($url);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            throw TokenDecoderException::forInvalidToken(new \Exception(
                'Invalid JWKS URL format'
            ));
        }

        // Get allowed domains from configuration
        $allowedDomains = $this->options['allowed_jwks_domains'] ?? [];

        // If no whitelist is provided, only allow the base_url domain
        if (empty($allowedDomains)) {
            $baseParsed = parse_url($this->options['base_url']);
            $allowedDomains = [$baseParsed['host'] ?? ''];
        }

        // Check if the host is in the whitelist
        $host = $parsed['host'];
        $isAllowed = false;
        foreach ($allowedDomains as $allowedDomain) {
            // Support wildcard subdomains (e.g., *.example.com)
            if (str_starts_with($allowedDomain, '*.')) {
                $domain = substr($allowedDomain, 2);
                if (str_ends_with($host, '.' . $domain) || $host === $domain) {
                    $isAllowed = true;
                    break;
                }
            } elseif ($host === $allowedDomain) {
                $isAllowed = true;
                break;
            }
        }

        if (!$isAllowed) {
            throw TokenDecoderException::forInvalidToken(new \Exception(sprintf(
                'JWKS URL host "%s" is not in the allowed domains whitelist',
                $host
            )));
        }

        // Additional security check: ensure HTTPS or localhost
        if ($parsed['scheme'] === 'http' && !$this->isLocalhost($host)) {
            throw TokenDecoderException::forInvalidToken(new \Exception(
                'JWKS endpoint must use HTTPS for non-localhost hosts'
            ));
        }
    }

    /**
     * Check if the host is localhost or local development address.
     */
    private function isLocalhost(string $host): bool
    {
        return in_array($host, ['localhost', '127.0.0.1', '::1', '0.0.0.0'], true)
            || str_ends_with($host, '.localhost');
    }

    /**
     * Check if the host is allowed (not a private IP or blocked host).
     */
    private function isAllowedHost(string $host): bool
    {
        // Allow localhost
        if ($this->isLocalhost($host)) {
            return true;
        }

        // Check if it's an IP address
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            // Block private IP ranges
            if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return false;
            }
        }

        // Block common internal hostnames
        $blockedHosts = [
            'metadata.google.internal',
            '169.254.169.254', // AWS metadata
            'metadata',
            'internal',
        ];

        foreach ($blockedHosts as $blocked) {
            if (stripos($host, $blocked) !== false) {
                return false;
            }
        }

        return true;
    }
}
