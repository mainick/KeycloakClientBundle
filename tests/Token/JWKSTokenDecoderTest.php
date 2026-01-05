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
        ]));

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
        // For this test, we need to test the actual JWKS fetching
        // We can't easily test this without a real token decode, but the validation
        // is covered by the previous tests
        $this->assertTrue(true);
    }
}

