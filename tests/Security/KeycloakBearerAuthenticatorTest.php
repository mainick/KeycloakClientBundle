<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Security;

use Firebase\JWT\JWT;
use Mainick\KeycloakClientBundle\Provider\KeycloakClient;
use Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakBearerAuthenticator;
use Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakOptionalBearerAuthenticator;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class KeycloakBearerAuthenticatorTest extends TestCase
{
    private const ISSUER = 'https://sso.example.test/realms/demo';

    private static string $privateKey;
    private static string $publicKeyBody;
    private static string $otherPrivateKey;

    public static function setUpBeforeClass(): void
    {
        [self::$privateKey, self::$publicKeyBody] = self::generateKeyPair();
        [self::$otherPrivateKey] = self::generateKeyPair();
    }

    /**
     * @return array{string, string}
     */
    private static function generateKeyPair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);
        $publicBody = trim(str_replace(['-----BEGIN PUBLIC KEY-----', '-----END PUBLIC KEY-----', "\n"], '', $details['key']));

        return [$privatePem, $publicBody];
    }

    /**
     * @param array<string,mixed> $claims
     */
    private function token(array $claims = [], ?string $privateKey = null): string
    {
        return JWT::encode([
            'exp' => time() + 300,
            'iat' => time(),
            'iss' => self::ISSUER,
            'sub' => 'user-1',
            'typ' => 'Bearer',
            'azp' => 'business-app',
            'preferred_username' => 'mario',
            'email' => 'mario@example.test',
            'email_verified' => true,
            'realm_access' => ['roles' => ['ROLE_REALM']],
            'resource_access' => [
                'business-app' => ['roles' => ['ROLE_AGENCY_BOOKINGS']],
                'admin-app' => ['roles' => ['ROLE_ADMIN']],
            ],
            ...$claims,
        ], $privateKey ?? self::$privateKey, 'RS256');
    }

    private function client(?string $issuer = self::ISSUER): KeycloakClient
    {
        return new KeycloakClient(
            new NullLogger(),
            true,
            'http://keycloak.internal:8080',
            'demo',
            'api',
            encryption_algorithm: 'RS256',
            encryption_key: self::$publicKeyBody,
            issuer: $issuer,
        );
    }

    /**
     * @param string[]                $allowedClients
     * @param array<string, string[]> $clientRoles
     */
    private function authenticator(
        string $rolesSource = 'authorized_party',
        array $allowedClients = [],
        array $clientRoles = [],
        ?string $issuer = self::ISSUER,
    ): KeycloakBearerAuthenticator {
        return new KeycloakBearerAuthenticator(new NullLogger(), $this->client($issuer), $rolesSource, $allowedClients, $clientRoles);
    }

    private function request(string $token): Request
    {
        return new Request(server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]);
    }

    private function authenticatedUser(KeycloakBearerAuthenticator $authenticator, string $token): KeycloakResourceOwner
    {
        $user = $authenticator->authenticate($this->request($token))->getUser();
        $this->assertInstanceOf(KeycloakResourceOwner::class, $user);

        return $user;
    }

    public function testSupportsOnlyBearerAuthorizationHeaders(): void
    {
        $authenticator = $this->authenticator();

        $this->assertTrue($authenticator->supports($this->request('abc')));
        $this->assertFalse($authenticator->supports(new Request()));
        $this->assertFalse($authenticator->supports(new Request(server: ['HTTP_AUTHORIZATION' => 'Basic abc'])));
    }

    public function testValidTokenBuildsTheUserFromTheVerifiedClaims(): void
    {
        $user = $this->authenticatedUser($this->authenticator(), $this->token());

        $this->assertSame('user-1', $user->getId());
        $this->assertSame('business-app', $user->getAuthorizedParty());
        $this->assertSame('mario', $user->getUserIdentifier());
    }

    public function testExpiredTokenIsRejected(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->authenticator()->authenticate($this->request($this->token(['exp' => time() - 10])));
    }

    public function testTokenSignedWithAnotherKeyIsRejected(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->authenticator()->authenticate($this->request($this->token(privateKey: self::$otherPrivateKey)));
    }

    public function testTokenOfAnotherIssuerIsRejected(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->authenticator()->authenticate($this->request($this->token(['iss' => 'https://evil.example.test/realms/demo'])));
    }

    public function testIssuerOnlyHasToContainTheRealmWhenNoIssuerIsConfigured(): void
    {
        $user = $this->authenticatedUser(
            $this->authenticator(issuer: null),
            $this->token(['iss' => 'http://localhost:8010/realms/demo']),
        );

        $this->assertSame('user-1', $user->getId());
    }

    public function testClientOutsideTheAllowedListIsRejected(): void
    {
        $authenticator = $this->authenticator(allowedClients: ['consumer-app', 'business-app']);

        $this->assertSame('user-1', $this->authenticatedUser($authenticator, $this->token())->getId());

        $this->expectException(AuthenticationException::class);
        $authenticator->authenticate($this->request($this->token(['azp' => 'account-console'])));
    }

    public function testRolesSourceAllKeepsRealmAndEveryClientRole(): void
    {
        $user = $this->authenticatedUser($this->authenticator(rolesSource: 'all'), $this->token());

        $this->assertEqualsCanonicalizing(['ROLE_REALM', 'ROLE_AGENCY_BOOKINGS', 'ROLE_ADMIN'], $user->getRoles());
    }

    public function testRolesSourceAuthorizedPartyKeepsOnlyTheRolesOfTheTokenClient(): void
    {
        $user = $this->authenticatedUser($this->authenticator(), $this->token());

        $this->assertSame(['ROLE_AGENCY_BOOKINGS'], $user->getRoles());
    }

    public function testClientRolesAreAddedForTheTokenClient(): void
    {
        $authenticator = $this->authenticator(clientRoles: [
            'business-app' => ['ROLE_AREA_AGENCY'],
            'admin-app' => ['ROLE_AREA_ADMIN'],
        ]);

        $user = $this->authenticatedUser($authenticator, $this->token());

        $this->assertEqualsCanonicalizing(['ROLE_AGENCY_BOOKINGS', 'ROLE_AREA_AGENCY'], $user->getRoles());
    }

    public function testOrganizationsAreAvailableOnTheUser(): void
    {
        $user = $this->authenticatedUser($this->authenticator(), $this->token(['organization' => ['acme']]));

        $this->assertSame(['acme'], array_map(static fn ($organization) => $organization->alias, $user->getOrganizations()));
    }

    public function testFailureReturnsUnauthorizedJson(): void
    {
        $response = $this->authenticator()->onAuthenticationFailure(new Request(), new AuthenticationException('Invalid token'));

        $this->assertInstanceOf(Response::class, $response);
        $this->assertSame(Response::HTTP_UNAUTHORIZED, $response->getStatusCode());
        $this->assertJsonStringEqualsJsonString('{"message":"Invalid token"}', (string) $response->getContent());
    }

    public function testOptionalAuthenticatorLetsTheRequestContinueOnFailure(): void
    {
        $authenticator = new KeycloakOptionalBearerAuthenticator(new NullLogger(), $this->client(), 'authorized_party', [], []);

        $this->assertNull($authenticator->onAuthenticationFailure(new Request(), new AuthenticationException('Invalid token')));
        $user = $authenticator->authenticate($this->request($this->token()))->getUser();
        $this->assertInstanceOf(KeycloakResourceOwner::class, $user);
    }
}
