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
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mainick\KeycloakClientBundle\Tests\Service\Support\ExecuteCommandTestHelperTrait;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class GroupsServiceTest extends TestCase
{
    use ExecuteCommandTestHelperTrait;

    private GroupsService $groupsService;
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

        $this->groupsService = new GroupsService(
            $this->logger,
            $this->keycloakAdminClient
        );

        $reflection = new \ReflectionClass($this->groupsService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setValue($this->groupsService, $this->serializer);
    }

    public function testAll(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '[{"id":"group1","name":"group1"},{"id":"group2","name":"group2"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups', $this->callback(function($options) {
                return isset($options['headers']['Authorization']) &&
                       $options['headers']['Authorization'] === 'Bearer mock_token';
            }))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, GroupCollection::class)
            ->willReturn($groupCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups?briefRepresentation=true', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, GroupCollection::class)
            ->willReturn($groupCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/count', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/children', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, GroupCollection::class)
            ->willReturn($groupCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $group = new GroupRepresentation();
        $group->id = 'group1';
        $group->name = 'group1';
        $group->path = '/group1';

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, GroupRepresentation::class)
            ->willReturn($group);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(201, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups', $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(201, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups/'.$parentGroupId.'/children', $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('PUT', 'admin/realms/'.$realm.'/groups/'.$groupId, $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/groups/'.$groupId, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/members', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, UserCollection::class)
            ->willReturn($userCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RoleCollection::class)
            ->willReturn($roleCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm/available', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RoleCollection::class)
            ->willReturn($roleCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm', $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/realm', $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RoleCollection::class)
            ->willReturn($roleCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid.'/available', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

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
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RoleCollection::class)
            ->willReturn($roleCollection);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid, $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/groups/'.$groupId.'/role-mappings/clients/'.$clientUuid, $this->callback(function($options) {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->groupsService->removeClientRole($realm, $clientUuid, $groupId, $role);

        // then
        $this->assertTrue($result);
    }
}
