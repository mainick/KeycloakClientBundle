<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Service;

use GuzzleHttp\ClientInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakAdminClient;
use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Serializer\Serializer;
use Mainick\KeycloakClientBundle\Service\Criteria;
use Mainick\KeycloakClientBundle\Service\GroupsService;
use Mainick\KeycloakClientBundle\Service\HttpMethodEnum;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class GroupsServiceTest extends TestCase
{
    private GroupsService $groupsService;
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

        $this->groupsService = new GroupsService(
            $this->logger,
            $this->keycloakAdminClient
        );
        $this->groupsService->adminAccessToken = $this->adminAccessToken;

        $reflection = new \ReflectionClass($this->groupsService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setAccessible(true);
        $serializerProperty->setValue($this->groupsService, $this->serializer);
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
        $responseBody = '[{"id":"group1","name":"group1"},{"id":"group2","name":"group2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups', m::on(function($options) {
                return isset($options['headers']['Authorization']) &&
                       $options['headers']['Authorization'] === 'Bearer mock_token';
            }))
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
        $result = $this->groupsService->all($realm);

        // then
        $this->assertInstanceOf(GroupCollection::class, $result);
        $this->assertSame($groupCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('group1', $result->jsonSerialize()[0]->name);
        $this->assertSame('group2', $result->jsonSerialize()[1]->name);
    }

    public function testAllWithCriteria(): void
    {
        // given
        $criteria = new Criteria(['briefRepresentation' => 'true']);
        $realm = 'test-realm';
        $responseBody = '[{"id":"group1","name":"group1"},{"id":"group2","name":"group2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups?briefRepresentation=true', m::type('array'))
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
        $result = $this->groupsService->all($realm, $criteria);

        // then
        $this->assertInstanceOf(GroupCollection::class, $result);
        $this->assertSame($groupCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('group1', $result->jsonSerialize()[0]->name);
        $this->assertSame('group2', $result->jsonSerialize()[1]->name);
    }

    public function testCount(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '2';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/count', m::type('array'))
            ->andReturn($response);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, 'array')
            ->andReturn(2);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->count($realm);

        // then
        $this->assertIsInt($result);
        $this->assertEquals(2, $result);
    }

    public function testChildren(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'parent-group';
        $responseBody = '[{"id":"child1","name":"child1"},{"id":"child2","name":"child2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/children', m::type('array'))
            ->andReturn($response);

        $groupCollection = new GroupCollection();
        $child1 = new GroupRepresentation();
        $child1->id = 'child1';
        $child1->name = 'child1';
        $child2 = new GroupRepresentation();
        $child2->id = 'child2';
        $child2->name = 'child2';
        $groupCollection->add($child1);
        $groupCollection->add($child2);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, GroupCollection::class)
            ->andReturn($groupCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->children($realm, $groupId);

        // then
        $this->assertInstanceOf(GroupCollection::class, $result);
        $this->assertSame($groupCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('child1', $result->jsonSerialize()[0]->name);
        $this->assertSame('child2', $result->jsonSerialize()[1]->name);
    }

    public function testGet(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $responseBody = '{"id":"group1","name":"group1","path":"/group1"}';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId, m::type('array'))
            ->andReturn($response);

        $group = new GroupRepresentation();
        $group->id = 'group1';
        $group->name = 'group1';
        $group->path = '/group1';

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, GroupRepresentation::class)
            ->andReturn($group);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->get($realm, $groupId);

        // then
        $this->assertInstanceOf(GroupRepresentation::class, $result);
        $this->assertSame($group, $result);
        $this->assertSame('group1', $result->id);
        $this->assertSame('group1', $result->name);
        $this->assertSame('/group1', $result->path);
    }

    public function testCreate(): void
    {
        // given
        $realm = 'test-realm';
        $group = new GroupRepresentation();
        $group->name = 'new-group';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(201);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->create($realm, $group);

        // then
        $this->assertTrue($result);
    }

    public function testCreateChild(): void
    {
        // given
        $realm = 'test-realm';
        $parentGroupId = 'parent-group';
        $group = new GroupRepresentation();
        $group->name = 'child-group';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(201);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups/'.$parentGroupId.'/children', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->createChild($realm, $parentGroupId, $group);

        // then
        $this->assertTrue($result);
    }

    public function testUpdate(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $group = new GroupRepresentation();
        $group->id = 'group1';
        $group->name = 'updated-group';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('PUT', 'admin/realms/'.$realm.'/groups/'.$groupId, m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->update($realm, $groupId, $group);

        // then
        $this->assertTrue($result);
    }

    public function testDelete(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/groups/'.$groupId, m::type('array'))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->delete($realm, $groupId);

        // then
        $this->assertTrue($result);
    }

    public function testUsers(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $responseBody = '[{"id":"user1","username":"user1"},{"id":"user2","username":"user2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/members', m::type('array'))
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
        $result = $this->groupsService->users($realm, $groupId);

        // then
        $this->assertInstanceOf(UserCollection::class, $result);
        $this->assertSame($userCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('user1', $result->jsonSerialize()[0]->username);
        $this->assertSame('user2', $result->jsonSerialize()[1]->username);
    }

    public function testRealmRoles(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm', m::type('array'))
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
        $result = $this->groupsService->realmRoles($realm, $groupId);

        // then
        $this->assertInstanceOf(RoleCollection::class, $result);
        $this->assertSame($roleCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('role1', $result->jsonSerialize()[0]->name);
        $this->assertSame('role2', $result->jsonSerialize()[1]->name);
    }

    public function testAvailableRealmRoles(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $responseBody = '[{"id":"role3","name":"role3"},{"id":"role4","name":"role4"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm/available', m::type('array'))
            ->andReturn($response);

        $roleCollection = new RoleCollection();
        $role3 = new RoleRepresentation();
        $role3->id = 'role3';
        $role3->name = 'role3';
        $role4 = new RoleRepresentation();
        $role4->id = 'role4';
        $role4->name = 'role4';
        $roleCollection->add($role3);
        $roleCollection->add($role4);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, RoleCollection::class)
            ->andReturn($roleCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->availableRealmRoles($realm, $groupId);

        // then
        $this->assertInstanceOf(RoleCollection::class, $result);
        $this->assertSame($roleCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('role3', $result->jsonSerialize()[0]->name);
        $this->assertSame('role4', $result->jsonSerialize()[1]->name);
    }

    public function testAddRealmRole(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $role = new RoleRepresentation();
        $role->id = 'role3';
        $role->name = 'role3';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->addRealmRole($realm, $groupId, $role);

        // then
        $this->assertTrue($result);
    }

    public function testRemoveRealmRole(): void
    {
        // given
        $realm = 'test-realm';
        $groupId = 'group1';
        $role = new RoleRepresentation();
        $role->id = 'role1';
        $role->name = 'role1';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->removeRealmRole($realm, $groupId, $role);

        // then
        $this->assertTrue($result);
    }

    public function testClientRoles(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $groupId = 'group1';
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid, m::type('array'))
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
        $result = $this->groupsService->clientRoles($realm, $clientUuid, $groupId);

        // then
        $this->assertInstanceOf(RoleCollection::class, $result);
        $this->assertSame($roleCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('role1', $result->jsonSerialize()[0]->name);
        $this->assertSame('role2', $result->jsonSerialize()[1]->name);
    }

    public function testAvailableClientRoles(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $groupId = 'group1';
        $responseBody = '[{"id":"role3","name":"role3"},{"id":"role4","name":"role4"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid.'/available', m::type('array'))
            ->andReturn($response);

        $roleCollection = new RoleCollection();
        $role3 = new RoleRepresentation();
        $role3->id = 'role3';
        $role3->name = 'role3';
        $role4 = new RoleRepresentation();
        $role4->id = 'role4';
        $role4->name = 'role4';
        $roleCollection->add($role3);
        $roleCollection->add($role4);

        $this->serializer
            ->shouldReceive('deserialize')
            ->with($responseBody, RoleCollection::class)
            ->andReturn($roleCollection);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->availableClientRoles($realm, $clientUuid, $groupId);

        // then
        $this->assertInstanceOf(RoleCollection::class, $result);
        $this->assertSame($roleCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('role3', $result->jsonSerialize()[0]->name);
        $this->assertSame('role4', $result->jsonSerialize()[1]->name);
    }

    public function testAddClientRole(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $groupId = 'group1';
        $role = new RoleRepresentation();
        $role->id = 'role3';
        $role->name = 'role3';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid, m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->addClientRole($realm, $clientUuid, $groupId, $role);

        // then
        $this->assertTrue($result);
    }

    public function testRemoveClientRole(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $groupId = 'group1';
        $role = new RoleRepresentation();
        $role->id = 'role1';
        $role->name = 'role1';

        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid, m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->groupsService->removeClientRole($realm, $clientUuid, $groupId, $role);

        // then
        $this->assertTrue($result);
    }
}
