<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Service;

use GuzzleHttp\ClientInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakAdminClient;
use Mainick\KeycloakClientBundle\Representation\ClientRepresentation;
use Mainick\KeycloakClientBundle\Representation\Collection\ClientCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Serializer\Serializer;
use Mainick\KeycloakClientBundle\Service\ClientsService;
use Mainick\KeycloakClientBundle\Service\Criteria;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class ClientsServiceTest extends TestCase
{
    private ClientsService $clientsService;
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

        $this->keycloakAdminClient->shouldReceive('getAdminAccessToken')->andReturn($this->adminAccessToken);

        $this->clientsService = new ClientsService(
            $this->logger,
            $this->keycloakAdminClient
        );

        $reflection = new \ReflectionClass($this->clientsService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setAccessible(true);
        $serializerProperty->setValue($this->clientsService, $this->serializer);
    }

    protected function tearDown(): void
    {
        m::close();
        parent::tearDown();
    }

    public function testAll(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '[{"id":"client1","clientId":"client1"},{"id":"client2","clientId":"client2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET','admin/realms/'.$realm.'/clients', m::on(function($options) {
                return isset($options['headers']['Authorization']) &&
                       $options['headers']['Authorization'] === 'Bearer mock_token';
            }))
            ->andReturn($response);

        $clientCollection = new ClientCollection();
        $client1 = new ClientRepresentation();
        $client1->id = 'client1';
        $client1->clientId = 'client1';
        $client2 = new ClientRepresentation();
        $client2->id = 'client2';
        $client2->clientId = 'client2';
        $clientCollection->add($client1);
        $clientCollection->add($client2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, ClientCollection::class)
            ->andReturn($clientCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->all($realm);

        // then
        $this->assertInstanceOf(ClientCollection::class, $result);
        $this->assertSame($clientCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('client1', $result->jsonSerialize()[0]->clientId);
        $this->assertSame('client2', $result->jsonSerialize()[1]->clientId);
    }

    public function testAllWithCriteria(): void
    {
        // given
        $criteria = new Criteria(['briefRepresentation' => 'true']);
        $realm = 'test-realm';
        $responseBody = '[{"id":"client1","clientId":"client1"},{"id":"client2","clientId":"client2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/clients?briefRepresentation=true', m::type('array'))
            ->andReturn($response);

        $clientCollection = new ClientCollection();
        $client1 = new ClientRepresentation();
        $client1->id = 'client1';
        $client1->clientId = 'client1';
        $client2 = new ClientRepresentation();
        $client2->id = 'client2';
        $client2->clientId = 'client2';
        $clientCollection->add($client1);
        $clientCollection->add($client2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, ClientCollection::class)
            ->andReturn($clientCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->all($realm, $criteria);

        // then
        $this->assertInstanceOf(ClientCollection::class, $result);
        $this->assertSame($clientCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('client1', $result->jsonSerialize()[0]->clientId);
        $this->assertSame('client2', $result->jsonSerialize()[1]->clientId);
    }

    public function testGet(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '{"id":"client1","clientId":"client1"}';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/clients/client1', m::type('array'))
            ->andReturn($response);

        $client = new ClientRepresentation();
        $client->id = 'client1';
        $client->clientId = 'client1';

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, ClientRepresentation::class)
            ->andReturn($client);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->get($realm, 'client1');

        // then
        $this->assertInstanceOf(ClientRepresentation::class, $result);
        $this->assertSame($client, $result);
    }

    public function testCreate(): void
    {
        // given
        $realm = 'test-realm';
        $client = new ClientRepresentation();
        $client->id = 'client1';
        $client->clientId = 'client1';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(201);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('POST', 'admin/realms/'.$realm.'/clients', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->create($realm, $client);

        // then
        $this->assertTrue($result);
    }

    public function testUpdate(): void
    {
        // given
        $realm = 'test-realm';
        $client = new ClientRepresentation();
        $client->id = 'client1';
        $client->clientId = 'client1';
        $client->description = 'Updated description';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('PUT', 'admin/realms/'.$realm.'/clients/client1', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->update($realm, 'client1', $client);

        // then
        $this->assertTrue($result);
    }

    public function testDelete(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/clients/client1', m::type('array'))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->delete($realm, 'client1');

        // then
        $this->assertTrue($result);
    }
    public function testRoles(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles', m::type('array'))
            ->andReturn($response);

        $roleCollection = new RoleCollection();
        $role1 = new RoleRepresentation();
        $role1->id = 'role1';
        $role1->name = 'role1';
        $role2 = new RoleRepresentation();
        $role2->id = 'role2';
        $role2->name = 'role2';
        $roleCollection->add($role1);
        $roleCollection->add($role2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, RoleCollection::class)
            ->andReturn($roleCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->roles($realm, $clientUuid);

        // then
        $this->assertInstanceOf(RoleCollection::class, $result);
        $this->assertSame($roleCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('role1', $result->jsonSerialize()[0]->name);
        $this->assertSame('role2', $result->jsonSerialize()[1]->name);
    }

    public function testRole(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $roleName = 'role1';
        $responseBody = '{"id":"role1","name":"role1","description":"Test role"}';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName, m::type('array'))
            ->andReturn($response);

        $role = new RoleRepresentation();
        $role->id = 'role1';
        $role->name = 'role1';
        $role->description = 'Test role';

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, RoleRepresentation::class)
            ->andReturn($role);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->role($realm, $clientUuid, $roleName);

        // then
        $this->assertInstanceOf(RoleRepresentation::class, $result);
        $this->assertSame($role, $result);
        $this->assertSame('role1', $result->id);
        $this->assertSame('role1', $result->name);
        $this->assertSame('Test role', $result->description);
    }

    public function testCreateRole(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $role = new RoleRepresentation();
        $role->name = 'new-role';
        $role->description = 'New test role';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(201);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('POST', 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->createRole($realm, $clientUuid, $role);

        // then
        $this->assertTrue($result);
    }

    public function testUpdateRole(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $roleName = 'role1';
        $role = new RoleRepresentation();
        $role->name = 'role1';
        $role->description = 'Updated role description';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('PUT', 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName, m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->updateRole($realm, $clientUuid, $roleName, $role);

        // then
        $this->assertTrue($result);
    }

    public function testDeleteRole(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $roleName = 'role1';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName, m::type('array'))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->deleteRole($realm, $clientUuid, $roleName);

        // then
        $this->assertTrue($result);
    }

    public function testGetRoleGroups(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $roleName = 'role1';
        $responseBody = '[{"id":"group1","name":"group1"},{"id":"group2","name":"group2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName.'/groups', m::type('array'))
            ->andReturn($response);

        $groupCollection = new GroupCollection();
        $group1 = new GroupRepresentation();
        $group1->id = 'group1';
        $group1->name = 'group1';
        $group2 = new GroupRepresentation();
        $group2->id = 'group2';
        $group2->name = 'group2';
        $groupCollection->add($group1);
        $groupCollection->add($group2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, GroupCollection::class)
            ->andReturn($groupCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->getRoleGroups($realm, $clientUuid, $roleName);

        // then
        $this->assertInstanceOf(GroupCollection::class, $result);
        $this->assertSame($groupCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('group1', $result->jsonSerialize()[0]->name);
        $this->assertSame('group2', $result->jsonSerialize()[1]->name);
    }

    public function testGetRoleUsers(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $roleName = 'role1';
        $responseBody = '[{"id":"user1","username":"user1"},{"id":"user2","username":"user2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/clients/'.$clientUuid.'/roles/'.$roleName.'/users', m::type('array'))
            ->andReturn($response);

        $userCollection = new UserCollection();
        $user1 = new UserRepresentation();
        $user1->id = 'user1';
        $user1->username = 'user1';
        $user2 = new UserRepresentation();
        $user2->id = 'user2';
        $user2->username = 'user2';
        $userCollection->add($user1);
        $userCollection->add($user2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, UserCollection::class)
            ->andReturn($userCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->clientsService->getRoleUsers($realm, $clientUuid, $roleName);

        // then
        $this->assertInstanceOf(UserCollection::class, $result);
        $this->assertSame($userCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('user1', $result->jsonSerialize()[0]->username);
        $this->assertSame('user2', $result->jsonSerialize()[1]->username);
    }
}
