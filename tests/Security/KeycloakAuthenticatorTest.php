<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Security;

use Firebase\JWT\JWT;
use Mainick\KeycloakClientBundle\DTO\KeycloakAuthorizationCodeEnum;
use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakClient;
use Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakAuthenticator;
use Mainick\KeycloakClientBundle\Security\User\KeycloakUserProvider;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

class KeycloakAuthenticatorTest extends TestCase
{
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

    protected KeycloakClient $iamClient;
    protected KeycloakAuthenticator $authenticator;
    protected KeycloakUserProvider $userProvider;
    protected KeycloakResourceOwner $resourceOwner;
    protected string $access_token;

    protected function setUp(): void
    {
        parent::setUp();
        if (!class_exists(AbstractAuthenticator::class)) {
            $this->markTestSkipped('The Symfony Security component is not installed.');
        }

        $jwt_tmp = sprintf($this->jwtTemplate, time() + 3600, time(), time());
        $this->access_token = JWT::encode(json_decode($jwt_tmp, true), self::ENCRYPTION_KEY, self::ENCRYPTION_ALGORITHM);

        $this->iamClient = m::mock(KeycloakClient::class);
        $accessToken = m::mock(AccessTokenInterface::class);
        $accessToken
            ->allows('getToken')
            ->andReturns($this->access_token);
        $accessToken
            ->allows('getRefreshToken')
            ->andReturns('mock_refresh_token');
        $this->iamClient
            ->allows('authenticateCodeGrant')
            ->with('authorization_code')
            ->andReturns($accessToken);

        $this->userProvider = m::mock(KeycloakUserProvider::class);
        $this->resourceOwner = m::mock(KeycloakResourceOwner::class);
        $this->userProvider
            ->allows('loadUserByIdentifier')
            ->with($accessToken)
            ->andReturns($this->resourceOwner);

        $this->authenticator = new KeycloakAuthenticator(
            $this->createMock(LoggerInterface::class),
            $this->iamClient,
            $this->userProvider
        );
    }

    protected function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthenticateSuccessfulAuthentication(): void
    {
        // given
        $session = m::mock(SessionInterface::class);
        $session
            ->allows('get')
            ->with(KeycloakAuthorizationCodeEnum::STATE_SESSION_KEY)
            ->andReturns('mock_state');

        $request = new Request();
        $request->query->add([
            KeycloakAuthorizationCodeEnum::STATE_KEY => 'mock_state',
            KeycloakAuthorizationCodeEnum::CODE_KEY => 'authorization_code',
        ]);
        $request->setSession($session);

        // when
        $passport = $this->authenticator->authenticate($request);

        // then
        $this->assertInstanceOf(SelfValidatingPassport::class, $passport);
        $userBadge = $passport->getBadge(UserBadge::class);
        $this->assertNotNull($userBadge);
        $this->assertEquals($this->resourceOwner, $userBadge->getUser());
        $this->assertEquals($this->access_token, $userBadge->getUserIdentifier());
    }

    public function testAuthenticateInvalidState(): void
    {
        // given
        $session = m::mock(SessionInterface::class);
        $session
            ->allows('get')
            ->with(KeycloakAuthorizationCodeEnum::STATE_SESSION_KEY)
            ->andReturns('some_state');

        $request = new Request();
        $request->query->add([
            KeycloakAuthorizationCodeEnum::STATE_KEY => 'invalid_state',
            KeycloakAuthorizationCodeEnum::CODE_KEY => 'authorization_code',
        ]);
        $request->setSession($session);

        // when
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('query state (invalid_state) is not the same as session state (some_state)');
        $this->authenticator->authenticate($request);
    }

    public function testAuthenticateMissingCode(): void
    {
        // given
        $session = m::mock(SessionInterface::class);
        $session
            ->allows('get')
            ->with(KeycloakAuthorizationCodeEnum::STATE_SESSION_KEY)
            ->andReturns('mock_state');

        $request = new Request();
        $request->query->add([
            KeycloakAuthorizationCodeEnum::STATE_KEY => 'mock_state',
        ]);
        $request->setSession($session);

        // when
        $this->expectException(AuthenticationException::class);
        $this->expectExceptionMessage('Authentication failed! Did you authorize our app?');
        $this->authenticator->authenticate($request);
    }
}
