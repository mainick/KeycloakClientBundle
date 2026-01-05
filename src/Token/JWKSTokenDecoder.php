<?php
declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Mainick\KeycloakClientBundle\Exception\TokenDecoderException;
use Mainick\KeycloakClientBundle\Interface\TokenDecoderInterface;

final readonly class JWKSTokenDecoder implements TokenDecoderInterface
{

    public function __construct(
        private ClientInterface $httpClient,
        private array $options
    )
    {
        foreach ($options as $allowOption => $value) {
            if (!\in_array($allowOption, ['base_url', 'realm', 'alg', 'http_timeout', 'http_connect_timeout', 'allowed_jwks_domains'], true)) {
                throw TokenDecoderException::forInvalidConfiguration(\sprintf(
                    "Unknown option '%s' for %s",
                    $allowOption,
                    self::class
                ));
            }
        }

        foreach (['base_url', 'realm'] as $requiredOption) {
            if (!\array_key_exists($requiredOption, $this->options) || $this->options[$requiredOption] === null || $this->options[$requiredOption] === '') {
                throw TokenDecoderException::forInvalidConfiguration(\sprintf(
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
            $parts = explode('.', $token);
            if (\count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
                throw TokenDecoderException::forDecodingError(
                    'Invalid JWT format: token must consist of header.payload.signature',
                    new \Exception('invalid token format')
                );
            }

            [$headerB64] = $parts;
            $header = json_decode($this->base64urlDecode($headerB64), true, 512, JSON_THROW_ON_ERROR);

            $kid = $header['kid'] ?? '';
            if (empty($kid)) {
                throw TokenDecoderException::forDecodingError('Missing kid in token header', new \Exception('kid not found'));
            }

            // Enforce a server-side algorithm instead of trusting the token header.
            // Default to RS256 (commonly used by Keycloak) if not explicitly configured.
            $algorithm = $this->options['alg'] ?? 'RS256';
            if (isset($header['alg']) && $algorithm !== (string) $header['alg']) {
                throw TokenDecoderException::forDecodingError(
                    sprintf('Token algorithm "%s" does not match expected algorithm "%s"', $header['alg'], $algorithm),
                    new \Exception('algorithm mismatch')
                );
            }

            $keyObject = $this->getKeyForKid($kid, $algorithm);
            $tokenDecoded = JWT::decode($token, $keyObject);

            $json = json_encode($tokenDecoded, JSON_THROW_ON_ERROR);

            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        }
        catch (\JsonException $e) {
            throw TokenDecoderException::forDecodingError('JSON parsing failed: ' . $e->getMessage(), $e);
        }
        catch (\Exception $e) {
            throw TokenDecoderException::forDecodingError($e->getMessage(), $e);
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

    private function getKeyForKid(string $kid, string $algorithm): Key
    {
        $jwksData = $this->fetchJwks();
        if (empty($jwksData['keys'])) {
            throw TokenDecoderException::forJwksError('No keys found in JWKS endpoint', new \Exception('Empty JWKS keys array'));
        }

        // Filter to only include signing keys
        $signingKeys = array_filter($jwksData['keys'], fn($jwk) => ($jwk['use'] ?? 'sig') === 'sig');
        if (empty($signingKeys)) {
            throw TokenDecoderException::forJwksError('No signing keys found in JWKS endpoint', new \Exception('No sig keys in JWKS'));
        }

        try {
            $keys = JWK::parseKeySet(['keys' => array_values($signingKeys)], $algorithm);
        } catch (\Exception $e) {
            throw TokenDecoderException::forJwksError(
                sprintf('Failed to parse JWKS: %s', $e->getMessage()),
                $e
            );
        }

        if (!isset($keys[$kid])) {
            throw TokenDecoderException::forJwksError(
                sprintf('No matching signing key found for kid: %s', $kid),
                new \Exception('Key ID not found in JWKS')
            );
        }

        return $keys[$kid];
    }

    private function fetchJwks(): array
    {
        $timeout = $this->options['http_timeout'] ?? 10;
        $connectTimeout = $this->options['http_connect_timeout'] ?? 5;
        $url = sprintf('%s/realms/%s/protocol/openid-connect/certs', $this->options['base_url'], $this->options['realm']);

        // Validate the constructed JWKS URL
        $this->validateJwksUrl($url);

        try {
            if ($this->httpClient === null) {
                throw TokenDecoderException::forJwksError(
                    'HTTP client is not configured; unable to fetch JWKS.',
                    new \RuntimeException('Missing HTTP client for JWKS retrieval')
                );
            }

            $response = $this->httpClient->request('GET', $url, [
                'timeout' => $timeout,
                'connect_timeout' => $connectTimeout,
            ]);
            $json = $response->getBody()->getContents();

            $data = json_decode($json, true, 512, JSON_THROW_ON_ERROR);

            return $data;
        } catch (GuzzleException $e) {
            throw TokenDecoderException::forJwksError(
                sprintf('Failed to fetch JWKS from %s: %s', $url, $e->getMessage()),
                $e
            );
        } catch (\JsonException $e) {
            throw TokenDecoderException::forJwksError(
                sprintf('Invalid JSON response from JWKS endpoint: %s', $e->getMessage()),
                $e
            );
        } catch (\Exception $e) {
            throw TokenDecoderException::forJwksError(
                sprintf('Unable to retrieve JWKS: %s', $e->getMessage()),
                $e
            );
        }
    }

    private function base64urlDecode(string $data): string
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw TokenDecoderException::forDecodingError(
                'Failed to decode base64url string',
                new \Exception('Invalid base64url format')
            );
        }

        return $decoded;
    }

    /**
     * Validate the base URL format to prevent SSRF attacks.
     *
     * @throws TokenDecoderException
     */
    private function validateBaseUrl(string $baseUrl): void
    {
        // Parse the URL
        $parsed = parse_url($baseUrl);
        if ($parsed === false || !isset($parsed['scheme'], $parsed['host'])) {
            throw TokenDecoderException::forInvalidConfiguration(sprintf(
                'Invalid base_url format: %s. Expected a valid URL with scheme and host.',
                $baseUrl
            ));
        }

        // Only allow HTTPS (or HTTP for localhost/development)
        if (!in_array($parsed['scheme'], ['https', 'http'], true)) {
            throw TokenDecoderException::forSecurityViolation(sprintf(
                'Invalid base_url scheme: %s. Only http and https are allowed.',
                $parsed['scheme']
            ));
        }

        // Enforce HTTPS for non-localhost environments
        if ($parsed['scheme'] === 'http' && !$this->isLocalhost($parsed['host'])) {
            throw TokenDecoderException::forSecurityViolation(sprintf(
                'HTTP is only allowed for localhost. Use HTTPS for: %s',
                $parsed['host']
            ));
        }

        // Prevent private IP ranges and localhost in production unless explicitly localhost
        if (!$this->isAllowedHost($parsed['host'])) {
            throw TokenDecoderException::forSecurityViolation(sprintf(
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
            throw TokenDecoderException::forSecurityViolation(
                'Invalid JWKS URL format'
            );
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
                if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                    $isAllowed = true;
                    break;
                }
            } elseif ($host === $allowedDomain) {
                $isAllowed = true;
                break;
            }
        }

        if (!$isAllowed) {
            throw TokenDecoderException::forSecurityViolation(sprintf(
                'JWKS URL host "%s" is not in the allowed domains whitelist',
                $host
            ));
        }

        // Additional security check: ensure HTTPS or localhost
        if ($parsed['scheme'] === 'http' && !$this->isLocalhost($host)) {
            throw TokenDecoderException::forSecurityViolation(
                'JWKS endpoint must use HTTPS for non-localhost hosts'
            );
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
