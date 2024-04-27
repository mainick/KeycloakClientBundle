<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Provider;

use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use Mainick\KeycloakClientBundle\Provider\KeycloakClient;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;

class KeycloakClientTest extends TestCase
{
    use QueryBuilderTrait;

    public const ENCRYPTION_KEY = <<<EOD
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t
0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4
ehde/zUxo6UvS7UrBQIDAQAB
-----END PUBLIC KEY-----
EOD;

    public const ENCRYPTION_ALGORITHM = 'HS256';

    private $jwtTemplate = <<<EOF
{
  "exp": "%s",
  "iat": "%s",
  "jti": "e11a85c8-aa91-4f75-9088-57db4586f8b9",
  "iss": "https://example.org/auth/realms/test-realm",
  "aud": "account",
  "nbf": "%s",
  "sub": "4332085e-b944-4acc-9eb1-27d8f5405f3e",
  "typ": "Bearer",
  "azp": "test-app",
  "session_state": "c90c8e0d-aabb-4c71-b8a8-e88792cacd96",
  "acr": "1",
  "realm_access": {
    "roles": [
      "default-roles-test-realm",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    },
    "test-app": {
      "roles": [
        "test-app-role-user"
      ]
    }
  },
  "scope": "openid email profile",
  "groups": [
    "test-app-group-user",
    "test-app-group-admin"
  ],
  "sid": "c90c8e0d-aabb-4c71-b8a8-e88792cacd96",
  "address": {},
  "email_verified": true,
  "name": "Test User",
  "preferred_username": "test-user",
  "given_name": "Test",
  "family_name": "User",
  "email": "test-user@example.org"
}
EOF;

    protected KeycloakClient $keycloakClient;
    protected string $access_token;

    protected function setUp(): void
    {
        parent::setUp();
        $this->keycloakClient = new KeycloakClient(
            $this->createMock(LoggerInterface::class),
            true,
            'http://mock.url/auth',
            'mock_realm',
            'test-app',
            'mock_secret',
            'none',
        );

        $jwt_tmp = sprintf($this->jwtTemplate, time() + 3600, time(), time());
        $this->access_token = JWT::encode(json_decode($jwt_tmp, true), self::ENCRYPTION_KEY, self::ENCRYPTION_ALGORITHM);
    }

    protected function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testRefreshToken(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(2)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $refreshToken = $this->keycloakClient->refreshToken($token);

        // then
        $this->assertEquals($this->access_token, $refreshToken->getToken());
        $this->assertEquals('mock_refresh_token', $refreshToken->getRefreshToken());
    }

    public function testVerifyToken(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $user = $this->keycloakClient->verifyToken($token);

        // then
        $this->assertEquals('test-user', $user->username);
        $this->assertEquals('Test', $user->firstName);
        $this->assertEquals('User', $user->lastName);
    }

    public function testUserInfo(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $jwt_tmp = sprintf($this->jwtTemplate, time() + 3600, time(), time());
        $getResourceOwnerStream = $this->createMock(StreamInterface::class);
        $getResourceOwnerStream
            ->method('__toString')
            ->willReturn($jwt_tmp);

        $getResourceOwnerResponse = m::mock(ResponseInterface::class);
        $getResourceOwnerResponse
            ->allows('getBody')
            ->andReturns($getResourceOwnerStream);
        $getResourceOwnerResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->allows('send')
            ->andReturns($getAccessTokenResponse, $getResourceOwnerResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $user = $this->keycloakClient->userInfo($token);

        // then
        $this->assertEquals('test-user', $user->username);
        $this->assertEquals('Test', $user->firstName);
        $this->assertEquals('User', $user->lastName);
        $this->assertEquals('test-user@example.org', $user->email);
    }

    public function testAuthenticate(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');

        // then
        $this->assertEquals($this->access_token, $token->getToken());
        $this->assertEquals(time() + 3600, $token->getExpires());
        $this->assertEquals('mock_refresh_token', $token->getRefreshToken());
        $this->assertIsArray($token->getValues());
        $this->assertArrayHasKey('scope', $token->getValues());
    }

    public function testAuthenticateByCode()
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticateCodeGrant('mock_code');

        // then
        $this->assertEquals($this->access_token, $token->getToken());
        $this->assertEquals(time() + 3600, $token->getExpires());
        $this->assertEquals('mock_refresh_token', $token->getRefreshToken());
        $this->assertIsArray($token->getValues());
        $this->assertArrayHasKey('scope', $token->getValues());
    }

    public function testGetRolesUser(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $user = $this->keycloakClient->verifyToken($token);
        $roles_name = array_map(fn ($role) => $role->name, $user->applicationRoles);

        // then
        $this->assertIsArray($user->applicationRoles);
        $this->assertContains('test-app-role-user', $roles_name);
    }

    public function testHasRoleInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $hasRole = $this->keycloakClient->hasRole($token, 'test-app-role-user');

        // then
        $this->assertTrue($hasRole);
    }

    public function testHasAnyRoleInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $anyRole = $this->keycloakClient->hasAnyRole($token, ['test-app-role-user', 'test-app-role-admin']);

        // then
        $this->assertTrue($anyRole);
    }

    public function testHasAllRolesInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $allRoles = $this->keycloakClient->hasAllRoles($token, ['test-app-role-user', 'view-profile']);

        // then
        $this->assertTrue($allRoles);
    }

    public function testGetGroupsUser(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $user = $this->keycloakClient->verifyToken($token);
        $groups_name = array_map(fn ($group) => $group->name, $user->groups);

        // then
        $this->assertIsArray($user->groups);
        $this->assertContains('test-app-group-user', $groups_name);
    }

    public function testHasGroupInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $hasGroup = $this->keycloakClient->hasGroup($token, 'test-app-group-user');

        // then
        $this->assertTrue($hasGroup);
    }

    public function testHasAnyGroupInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $anyGroup = $this->keycloakClient->hasAnyGroup($token, ['test-app-group-user', 'test-app-group-not-exists']);

        // then
        $this->assertTrue($anyGroup);
    }

    public function testHasAllGroupsInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $allGroups = $this->keycloakClient->hasAllGroups($token, ['test-app-group-user', 'test-app-group-admin']);

        // then
        $this->assertTrue($allGroups);
    }

    public function testGetScopeUser(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $user = $this->keycloakClient->verifyToken($token);
        $scope_name = array_map(fn ($scope) => $scope->name, $user->scope);

        // then
        $this->assertIsArray($user->scope);
        $this->assertContains('openid', $scope_name);
    }

    public function testHasScopeInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $hasScope = $this->keycloakClient->hasScope($token, 'openid');

        // then
        $this->assertTrue($hasScope);
    }

    public function testHasAnyScopeInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $hasAnyScope = $this->keycloakClient->hasAnyScope($token, ['openid', 'roles_clients']);

        // then
        $this->assertTrue($hasAnyScope);
    }

    public function testHasAllScopesInUserSOnes(): void
    {
        // given
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');

        $getAccessTokenResponse = m::mock(ResponseInterface::class);
        $getAccessTokenResponse
            ->allows('getBody')
            ->andReturns($getAccessTokenStream);
        $getAccessTokenResponse
            ->allows('getHeader')
            ->andReturns(['content-type' => 'application/json']);

        $client = m::mock(ClientInterface::class);
        $client
            ->expects('send')
            ->times(1)
            ->andReturns($getAccessTokenResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');
        $hasAllScopes = $this->keycloakClient->hasAllScopes($token, ['openid', 'profile']);

        // then
        $this->assertTrue($hasAllScopes);
    }
}
