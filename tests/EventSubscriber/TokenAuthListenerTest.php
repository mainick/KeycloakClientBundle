<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\EventSubscriber;

use Firebase\JWT\JWT;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use Mainick\KeycloakClientBundle\Annotation\ExcludeTokenValidationAttribute;
use Mainick\KeycloakClientBundle\EventSubscriber\TokenAuthListener;
use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakClient;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class MyController
{
    #[ExcludeTokenValidationAttribute]
    public function excludedRouteAction(): Response
    {
        return new Response('Excluded route', Response::HTTP_OK, ['Content-Type' => 'text/plain']);
    }
}

class TokenAuthListenerTest extends TestCase
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
    "test-app-group-user"
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
            'mock_client_id',
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

    public function testCheckValidTokenOnRequest(): void
    {
        // given
        // mock access token
        $getAccessTokenStream = $this->createMock(StreamInterface::class);
        $getAccessTokenStream
            ->method('__toString')
            ->willReturn('{"access_token":"'.$this->access_token.'","expires_in":3600,"refresh_token":"mock_refresh_token","scope":"email","token_type":"bearer"}');
        $getAccessTokenResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $getAccessTokenResponse
            ->shouldReceive('getBody')
            ->andReturn($getAccessTokenStream);
        $getAccessTokenResponse
            ->shouldReceive('getHeader')
            ->andReturn(['content-type' => 'application/json']);

        // mock resource owner
        $jwt_tmp = sprintf($this->jwtTemplate, time() + 3600, time(), time());
        $getResourceOwnerStream = $this->createMock(StreamInterface::class);
        $getResourceOwnerStream
            ->method('__toString')
            ->willReturn($jwt_tmp);
        $getResourceOwnerResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $getResourceOwnerResponse
            ->shouldReceive('getBody')
            ->andReturn($getResourceOwnerStream);
        $getResourceOwnerResponse
            ->shouldReceive('getHeader')
            ->andReturn(['content-type' => 'application/json']);

        // mock http client
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client
            ->shouldReceive('send')
            ->andReturn($getAccessTokenResponse, $getResourceOwnerResponse);
        $this->keycloakClient->setHttpClient($client);

        // when
        $token = $this->keycloakClient->authenticate('mock_user', 'mock_password');

        // mock event request
        $logger = $this->createMock(LoggerInterface::class);
        $tokenAuthListener = new TokenAuthListener($logger, $this->keycloakClient);
        $request = new Request();
        $request->headers->set('X-Auth-Token', $token->getToken());
        $eventRequest = new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST
        );

        // call checkValidToken
        $tokenAuthListener->checkValidToken($eventRequest);

        // then
        $user = $request->attributes->get('user');
        $this->assertEquals('test-user', $user->username);
    }

    public function testCheckValidTokenExcludesRouteWithAttribute(): void
    {
        // given
        $logger = $this->createMock(LoggerInterface::class);
        $iamClient = $this->createMock(IamClientInterface::class);
        $tokenAuthListener = new TokenAuthListener($logger, $iamClient);

        // when
        // Create a mock controller method with ExcludeTokenValidationAttribute
        $controllerMethodWithAttribute = 'Mainick\KeycloakClientBundle\Tests\EventSubscriber\MyController::excludedRouteAction';

        // Mock the request for a route with ExcludeTokenValidationAttribute
        $request = new Request();
        $request->attributes->set('_controller', $controllerMethodWithAttribute);
        $request->headers->set('X-Auth-Token', $this->access_token);

        // Mock the Event
        $eventRequest = new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST
        );

        // call checkValidToken
        $tokenAuthListener->checkValidToken($eventRequest);

        // then
        // Verify that the token validation was skipped for the route with ExcludeTokenValidationAttribute
        $this->assertNull($eventRequest->getResponse());
    }
}
