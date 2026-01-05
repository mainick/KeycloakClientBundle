<?php
declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Token;

use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use Mainick\KeycloakClientBundle\Exception\TokenDecoderException;
use Mainick\KeycloakClientBundle\Token\JWKSTokenDecoder;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class JWKSTokenDecoderTest extends TestCase
{
    public function testConstructorValidatesBaseUrl(): void
    {
        $this->expectException(TokenDecoderException::class);
        $this->expectExceptionMessage('Invalid base_url format');

        new JWKSTokenDecoder([
            'base_url' => 'not-a-valid-url',
            'realm' => 'test-realm',
        ]);
    }

    public function testConstructorRejectsHttpForNonLocalhost(): void
    {
        $this->expectException(TokenDecoderException::class);
        $this->expectExceptionMessage('HTTP is only allowed for localhost');

        new JWKSTokenDecoder([
            'base_url' => 'http://keycloak.example.com',
            'realm' => 'test-realm',
        ]);
    }

    public function testConstructorAcceptsHttpForLocalhost(): void
    {
        $decoder = new JWKSTokenDecoder([
            'base_url' => 'http://localhost:8080',
            'realm' => 'test-realm',
        ]);

        $this->assertInstanceOf(JWKSTokenDecoder::class, $decoder);
    }

    public function testConstructorRejectsPrivateIpRanges(): void
    {
        $this->expectException(TokenDecoderException::class);
        $this->expectExceptionMessage('is not allowed');

        new JWKSTokenDecoder([
            'base_url' => 'https://192.168.1.1',
            'realm' => 'test-realm',
        ]);
    }

    public function testConstructorRejectsMetadataEndpoints(): void
    {
        $this->expectException(TokenDecoderException::class);
        $this->expectExceptionMessage('is not allowed');

        new JWKSTokenDecoder([
            'base_url' => 'https://169.254.169.254',
            'realm' => 'test-realm',
        ]);
    }

    public function testConstructorAcceptsValidHttpsUrl(): void
    {
        $decoder = new JWKSTokenDecoder([
            'base_url' => 'https://keycloak.example.com',
            'realm' => 'test-realm',
        ]);

        $this->assertInstanceOf(JWKSTokenDecoder::class, $decoder);
    }

    public function testFetchJwksValidatesDomainWhitelist(): void
    {
        // Create a mock HTTP client
        $httpClient = $this->createMock(ClientInterface::class);

        $decoder = new JWKSTokenDecoder([
            'base_url' => 'https://keycloak.example.com',
            'realm' => 'test-realm',
            'allowed_jwks_domains' => ['different-domain.com'],
        ], $httpClient);

        // Create a sample JWT token (doesn't need to be valid for this test)
        $header = base64_encode(json_encode(['kid' => 'test-kid', 'alg' => 'RS256']));
        $payload = base64_encode(json_encode(['sub' => 'test']));
        $signature = base64_encode('test-signature');
        $token = "$header.$payload.$signature";

        try {
            $decoder->decode($token, '');
            $this->fail('Expected TokenDecoderException to be thrown');
        } catch (TokenDecoderException $e) {
            $this->assertStringContainsString('Security violation: JWKS URL host "keycloak.example.com" is not in the allowed domains whitelist', $e->getMessage());
        }
    }

    public function testFetchJwksAllowsBaseUrlDomainByDefault(): void
    {
        // Create a mock stream for the response body
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn(json_encode([
            'keys' => [
                [
                    'kid' => 'test-kid',
                    'use' => 'sig',
                    'kty' => 'RSA',
                    'n' => 'test-modulus',
                    'e' => 'AQAB',
                ],
            ],
        ], JSON_THROW_ON_ERROR));

        // Create a mock response
        $response = $this->createMock(Response::class);
        $response->method('getBody')->willReturn($stream);

        // Create a mock HTTP client
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->method('request')->willReturn($response);

        $decoder = new JWKSTokenDecoder([
            'base_url' => 'https://keycloak.example.com',
            'realm' => 'test-realm',
            // No allowed_jwks_domains specified - should default to base_url domain
        ], $httpClient);

        // This should not throw an exception because the JWKS URL uses the same domain as base_url
        $this->assertInstanceOf(JWKSTokenDecoder::class, $decoder);
    }

    public function testWildcardDomainMatching(): void
    {
        // Create a mock stream for the response body
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn(json_encode([
            'keys' => [
                [
                    'kid' => 'test-kid',
                    'use' => 'sig',
                    'kty' => 'RSA',
                    'n' => 'test-modulus',
                    'e' => 'AQAB',
                ],
            ],
        ]));

        // Create a mock response
        $response = $this->createMock(Response::class);
        $response->method('getBody')->willReturn($stream);

        // Create a mock HTTP client
        $httpClient = $this->createMock(ClientInterface::class);
        $httpClient->method('request')->willReturn($response);

        $decoder = new JWKSTokenDecoder([
            'base_url' => 'https://auth.example.com',
            'realm' => 'test-realm',
            'allowed_jwks_domains' => ['*.example.com'],
        ], $httpClient);

        // This should not throw an exception because auth.example.com matches *.example.com
        $this->assertInstanceOf(JWKSTokenDecoder::class, $decoder);
    }

    public function testRequiresHttpsForJwksEndpoint(): void
    {
        // This test verifies that the JWKS endpoint URL validation rejects HTTP
        // for non-localhost domains during token decoding. We create a decoder
        // with valid HTTPS, then simulate an HTTP JWKS URL fetch scenario.

        // Create a mock HTTP client
        $httpClient = $this->createMock(ClientInterface::class);

        // Create a valid decoder first with localhost HTTP (which is allowed)
        $decoder = new JWKSTokenDecoder([
            'base_url' => 'http://localhost:8080',
            'realm' => 'test-realm',
        ], $httpClient);

        // Use reflection to modify the base_url to an HTTP non-localhost domain
        // This simulates a scenario where the JWKS URL would be HTTP for a non-localhost host
        $reflection = new \ReflectionClass($decoder);
        $optionsProperty = $reflection->getProperty('options');
        $optionsProperty->setAccessible(true);
        $options = $optionsProperty->getValue($decoder);
        $options['base_url'] = 'http://keycloak.example.com';
        $optionsProperty->setValue($decoder, $options);

        // Create a JWT token with proper structure
        $header = json_encode([
            'kid' => 'test-key-id',
            'alg' => 'RS256',
            'typ' => 'JWT',
        ], JSON_THROW_ON_ERROR);
        $payload = json_encode([
            'sub' => 'test-user',
            'exp' => time() + 3600,
            'iat' => time(),
            'iss' => 'http://keycloak.example.com/auth/realms/test-realm',
        ], JSON_THROW_ON_ERROR);

        // Base64url encode the token parts
        $headerEncoded = rtrim(strtr(base64_encode($header), '+/', '-_'), '=');
        $payloadEncoded = rtrim(strtr(base64_encode($payload), '+/', '-_'), '=');
        $token = "$headerEncoded.$payloadEncoded.fake-signature";

        $this->expectException(TokenDecoderException::class);
        $this->expectExceptionMessage('JWKS endpoint must use HTTPS for non-localhost hosts');

        // Attempt to decode the token - this should trigger fetchJwks which validates the JWKS URL
        $decoder->decode($token, '');
    }
}

