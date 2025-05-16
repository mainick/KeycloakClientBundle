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
use Mainick\KeycloakClientBundle\Service\RolesService;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mockery as m;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class RolesServiceTest extends TestCase
{
    private RolesService $rolesService;
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

        $this->rolesService = new RolesService(
            $this->logger,
            $this->keycloakAdminClient
        );
        $this->rolesService->adminAccessToken = $this->adminAccessToken;

        $reflection = new \ReflectionClass($this->rolesService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setAccessible(true);
        $serializerProperty->setValue($this->rolesService, $this->serializer);
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
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles', m::on(function($options) {
                return isset($options['headers']['Authorization']) &&
                       $options['headers']['Authorization'] === 'Bearer mock_token';
            }))
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
        $result = $this->rolesService->all($realm);

        // then
        $this->assertInstanceOf(RoleCollection::class, $result);
        $this->assertSame($roleCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('role1', $result->jsonSerialize()[0]->name);
        $this->assertSame('role2', $result->jsonSerialize()[1]->name);
    }

    public function testAllWithCriteria(): void
    {
        // given
        $criteria = new Criteria(['briefRepresentation' => 'true']);
        $realm = 'test-realm';
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles?briefRepresentation=true', m::type('array'))
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
        $result = $this->rolesService->all($realm, $criteria);

        // then
        $this->assertInstanceOf(RoleCollection::class, $result);
        $this->assertSame($roleCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('role1', $result->jsonSerialize()[0]->name);
        $this->assertSame('role2', $result->jsonSerialize()[1]->name);
    }

    public function testGet(): void
    {
        // given
        $realm = 'test-realm';
        $roleName = 'role1';
        $responseBody = '{"id":"role1","name":"role1","description":"Test role"}';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName, m::type('array'))
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
        $result = $this->rolesService->get($realm, $roleName);

        // then
        $this->assertInstanceOf(RoleRepresentation::class, $result);
        $this->assertSame($role, $result);
        $this->assertSame('role1', $result->id);
        $this->assertSame('role1', $result->name);
        $this->assertSame('Test role', $result->description);
    }

    public function testCreate(): void
    {
        // given
        $realm = 'test-realm';
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
            ->with('POST', 'admin/realms/'.$realm.'/roles', m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->rolesService->create($realm, $role);

        // then
        $this->assertTrue($result);
    }

    public function testUpdate(): void
    {
        // given
        $realm = 'test-realm';
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
            ->with('PUT', 'admin/realms/'.$realm.'/roles/'.$roleName, m::on(function($options) {
                return isset($options['json']);
            }))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->rolesService->update($realm, $roleName, $role);

        // then
        $this->assertTrue($result);
    }

    public function testDelete(): void
    {
        // given
        $realm = 'test-realm';
        $roleName = 'role1';
        $responseBody = '';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(204);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/roles/'.$roleName, m::type('array'))
            ->andReturn($response);

        $this->logger->shouldReceive('info')->once();

        // when
        $result = $this->rolesService->delete($realm, $roleName);

        // then
        $this->assertTrue($result);
    }

    public function testGroups(): void
    {
        // given
        $realm = 'test-realm';
        $roleName = 'role1';
        $responseBody = '[{"id":"group1","name":"group1"},{"id":"group2","name":"group2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/groups', m::type('array'))
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
        $result = $this->rolesService->groups($realm, $roleName);

        // then
        $this->assertInstanceOf(GroupCollection::class, $result);
        $this->assertSame($groupCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('group1', $result->jsonSerialize()[0]->name);
        $this->assertSame('group2', $result->jsonSerialize()[1]->name);
    }

    public function testGroupsWithCriteria(): void
    {
        // given
        $realm = 'test-realm';
        $roleName = 'role1';
        $criteria = new Criteria(['first' => '0', 'max' => '10']);
        $responseBody = '[{"id":"group1","name":"group1"},{"id":"group2","name":"group2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/groups?first=0&max=10', m::type('array'))
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
        $result = $this->rolesService->groups($realm, $roleName, $criteria);

        // then
        $this->assertInstanceOf(GroupCollection::class, $result);
        $this->assertSame($groupCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('group1', $result->jsonSerialize()[0]->name);
        $this->assertSame('group2', $result->jsonSerialize()[1]->name);
    }

    public function testUsers(): void
    {
        // given
        $realm = 'test-realm';
        $roleName = 'role1';
        $responseBody = '[{"id":"user1","username":"user1"},{"id":"user2","username":"user2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/users', m::type('array'))
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
        $result = $this->rolesService->users($realm, $roleName);

        // then
        $this->assertInstanceOf(UserCollection::class, $result);
        $this->assertSame($userCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('user1', $result->jsonSerialize()[0]->username);
        $this->assertSame('user2', $result->jsonSerialize()[1]->username);
    }

    public function testUsersWithCriteria(): void
    {
        // given
        $realm = 'test-realm';
        $roleName = 'role1';
        $criteria = new Criteria(['first' => '0', 'max' => '10']);
        $responseBody = '[{"id":"user1","username":"user1"},{"id":"user2","username":"user2"}]';
        $stream = $this->createMock(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = m::mock(ResponseInterface::class);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($stream);

        $this->httpClient
            ->shouldReceive('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/users?first=0&max=10', m::type('array'))
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
        $result = $this->rolesService->users($realm, $roleName, $criteria);

        // then
        $this->assertInstanceOf(UserCollection::class, $result);
        $this->assertSame($userCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('user1', $result->jsonSerialize()[0]->username);
        $this->assertSame('user2', $result->jsonSerialize()[1]->username);
    }
}
