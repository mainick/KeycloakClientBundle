<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Service;

use GuzzleHttp\ClientInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakAdminClient;
use Mainick\KeycloakClientBundle\Representation\Collection\RealmCollection;
use Mainick\KeycloakClientBundle\Representation\RealmRepresentation;
use Mainick\KeycloakClientBundle\Serializer\Serializer;
use Mainick\KeycloakClientBundle\Service\Criteria;
use Mainick\KeycloakClientBundle\Service\RealmsService;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mainick\KeycloakClientBundle\Tests\Service\Support\ExecuteCommandTestHelperTrait;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class RealmsServiceTest extends TestCase
{
    use ExecuteCommandTestHelperTrait;

    private RealmsService $realmsService;
    private ClientInterface $httpClient;
    private KeycloakAdminClient $keycloakAdminClient;
    private LoggerInterface $logger;
    private Serializer $serializer;
    private AccessToken $adminAccessToken;

    protected function setUp(): void
    {
        parent::setUp();

        $this->httpClient = $this->createMock(ClientInterface::class);
        $this->keycloakAdminClient = $this->createStub(KeycloakAdminClient::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->serializer = $this->createMock(Serializer::class);

        $keycloakProvider = $this->createStub(Keycloak::class);
        $keycloakProvider->method('getHttpClient')->willReturn($this->httpClient);

        $this->keycloakAdminClient->method('getKeycloakProvider')->willReturn($keycloakProvider);
        $this->keycloakAdminClient->method('getBaseUrl')->willReturn('http://mock.url/auth');
        $this->keycloakAdminClient->method('getVersion')->willReturn('17.0.1');

        $this->adminAccessToken = new AccessToken();
        $this->adminAccessToken
            ->setToken('mock_token')
            ->setExpires(time() + 3600)
            ->setRefreshToken('mock_refresh_token')
            ->setValues(['scope' => 'email']);

        $this->keycloakAdminClient->method('getAdminAccessToken')->willReturn($this->adminAccessToken);

        $this->realmsService = new RealmsService(
            $this->logger,
            $this->keycloakAdminClient
        );

        $reflection = new \ReflectionClass($this->realmsService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setValue($this->realmsService, $this->serializer);
    }

    public function testAll(): void
    {
        // given
        $responseBody = '[{"id":"master","realm":"master"},{"id":"test","realm":"test"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms', $this->callback(function($options) {
                return isset($options['headers']['Authorization']) &&
                       $options['headers']['Authorization'] === 'Bearer mock_token';
            }))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RealmCollection::class)
            ->willReturn($realmCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms?briefRepresentation=true', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RealmCollection::class)
            ->willReturn($realmCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/test', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $realm = new RealmRepresentation();
        $realm->realm = 'test';

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RealmRepresentation::class)
            ->willReturn($realm);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(201, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/', $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('PUT', 'admin/realms/test', $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->realmsService->update('test', $realm);

        // then
        $this->assertTrue($result);
    }

    public function testDelete(): void
    {
        // given
        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/test', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->realmsService->delete('test');

        // then
        $this->assertTrue($result);
    }
}
