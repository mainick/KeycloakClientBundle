<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Service;

use GuzzleHttp\ClientInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakAdminClient;
use Mainick\KeycloakClientBundle\Representation\Collection\RealmCollection;
use Mainick\KeycloakClientBundle\Representation\RealmRepresentation;
use Mainick\KeycloakClientBundle\Serializer\Serializer;
use Mainick\KeycloakClientBundle\Service\Criteria;
use Mainick\KeycloakClientBundle\Service\HttpMethodEnum;
use Mainick\KeycloakClientBundle\Service\RealmsService;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;
use Symfony\Component\Serializer\SerializerInterface;

class RealmsServiceTest extends TestCase
{
    private RealmsService $realmsService;
    private m\MockInterface $httpClient;
    private m\MockInterface $keycloakAdminClient;
    private m\MockInterface $logger;
    private m\MockInterface $serializer;
    private AccessToken $adminAccessToken;

    protected function setUp(): void
    {
        parent::setUp();

        $this->httpClient = m::mock(ClientInterface::class);
        $this->keycloakAdminClient = m::mock(KeycloakAdminClient::class);
        $this->logger = m::mock(LoggerInterface::class);
        $this->serializer = m::mock(Serializer::class);

        $keycloakProvider = m::mock(Keycloak::class);
        $keycloakProvider->shouldReceive('getHttpClient')->andReturn($this->httpClient);

        $this->keycloakAdminClient->shouldReceive('getKeycloakProvider')->andReturn($keycloakProvider);
        $this->keycloakAdminClient->shouldReceive('getBaseUrl')->andReturn('http://mock.url/auth');
        $this->keycloakAdminClient->shouldReceive('getVersion')->andReturn('17.0.1');

        $this->adminAccessToken = new AccessToken();
        $this->adminAccessToken
            ->setToken('mock_token')
            ->setExpires(time() + 3600)
            ->setRefreshToken('mock_refresh_token')
            ->setValues(['scope' => 'email']);

        $this->realmsService = new RealmsService(
            $this->logger,
            $this->keycloakAdminClient
        );
        $this->realmsService->adminAccessToken = $this->adminAccessToken;

        $reflection = new \ReflectionClass($this->realmsService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setAccessible(true);
        $serializerProperty->setValue($this->realmsService, $this->serializer);
    }

    protected function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testAll(): void
    {
        // given
        $responseBody = '[{"id":"master","realm":"master"},{"id":"test","realm":"test"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms', m::on(function($options) {
                return isset($options['headers']['Authorization']) &&
                       $options['headers']['Authorization'] === 'Bearer mock_token';
            }))
            ->andReturn($response);

        $realmCollection = new RealmCollection();
        $realm1 = new RealmRepresentation();
        $realm1->id = 'master';
        $realm1->realm = 'master';
        $realm2 = new RealmRepresentation();
        $realm2->id = 'test';
        $realm2->realm = 'test';
        $realmCollection->add($realm1);
        $realmCollection->add($realm2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, RealmCollection::class)
            ->andReturn($realmCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->realmsService->all();

        // then
        $this->assertInstanceOf(RealmCollection::class, $result);
        $this->assertSame($realmCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('master', $result->jsonSerialize()[0]->id);
        $this->assertSame('test', $result->jsonSerialize()[1]->id);
    }

    public function testAllWithCriteria(): void
    {
        // given
        $criteria = new Criteria(['briefRepresentation' => 'true']);

        $responseBody = '[{"id":"master","realm":"master"},{"id":"test","realm":"test"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms?briefRepresentation=true', m::type('array'))
            ->andReturn($response);

        $realmCollection = new RealmCollection();
        $realm1 = new RealmRepresentation();
        $realm1->id = 'master';
        $realm1->realm = 'master';
        $realm2 = new RealmRepresentation();
        $realm2->id = 'test';
        $realm2->realm = 'test';
        $realmCollection->add($realm1);
        $realmCollection->add($realm2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, RealmCollection::class)
            ->andReturn($realmCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->realmsService->all($criteria);

        // then
        $this->assertInstanceOf(RealmCollection::class, $result);
        $this->assertSame($realmCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('master', $result->jsonSerialize()[0]->id);
        $this->assertSame('test', $result->jsonSerialize()[1]->id);
    }

    public function testGet(): void
    {
        // given
        $responseBody = '{"id":"test","realm":"test"}';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/test', m::type('array'))
            ->andReturn($response);

        $realm = new RealmRepresentation();
        $realm->realm = 'test';

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->realmsService->get('test');

        // then
        $this->assertInstanceOf(RealmRepresentation::class, $result);
        $this->assertSame($realm, $result);
    }

    public function testCreate(): void
    {
        // given
        $realm = new RealmRepresentation();
        $realm->realm = 'new-realm';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(201);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('POST', 'admin/realms/', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->realmsService->create($realm);

        // then
        $this->assertTrue($result);
    }

    public function testUpdate(): void
    {
        // given
        $realm = new RealmRepresentation();
        $realm->realm = 'test';
        $realm->displayName = 'Updated Test Realm';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('PUT', 'admin/realms/test', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->realmsService->update('test', $realm);

        // then
        $this->assertTrue($result);
    }

    public function testDelete(): void
    {
        // given
        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('DELETE', 'admin/realms/test', m::type('array'))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->realmsService->delete('test');

        // then
        $this->assertTrue($result);
    }
}
