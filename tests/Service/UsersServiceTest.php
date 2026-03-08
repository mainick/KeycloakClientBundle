<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Service;

use GuzzleHttp\ClientInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakAdminClient;
use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\RoleCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserSessionCollection;
use Mainick\KeycloakClientBundle\Representation\GroupRepresentation;
use Mainick\KeycloakClientBundle\Representation\RoleRepresentation;
use Mainick\KeycloakClientBundle\Representation\UPConfig;
use Mainick\KeycloakClientBundle\Representation\UserProfileMetadata;
use Mainick\KeycloakClientBundle\Representation\UserRepresentation;
use Mainick\KeycloakClientBundle\Representation\UserSessionRepresentation;
use Mainick\KeycloakClientBundle\Serializer\Serializer;
use Mainick\KeycloakClientBundle\Service\Criteria;
use Mainick\KeycloakClientBundle\Service\UsersService;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use Mainick\KeycloakClientBundle\Tests\Service\Support\ExecuteCommandTestHelperTrait;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class UsersServiceTest extends TestCase
{
    use ExecuteCommandTestHelperTrait;

    private UsersService $usersService;
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

        $this->usersService = new UsersService(
            $this->logger,
            $this->keycloakAdminClient
        );

        $reflection = new \ReflectionClass($this->usersService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setValue($this->usersService, $this->serializer);
    }

    public function testAll(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '[{"id":"user1","username":"user1"},{"id":"user2","username":"user2"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users', $this->callback(static function ($options): bool {
                return is_array($options)
                    && isset($options['headers']['Authorization'])
                    && 'Bearer mock_token' === $options['headers']['Authorization'];
            }))
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
        $result = $this->usersService->all($realm);

        // then
        $this->assertInstanceOf(UserCollection::class, $result);
        $this->assertSame($userCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('user1', $result->jsonSerialize()[0]->username);
        $this->assertSame('user2', $result->jsonSerialize()[1]->username);
    }

    public function testAllWithCriteria(): void
    {
        // given
        $criteria = new Criteria(['briefRepresentation' => 'true']);
        $realm = 'test-realm';
        $responseBody = '[{"id":"user1","username":"user1"},{"id":"user2","username":"user2"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users?briefRepresentation=true', $this->callback(static fn ($options): bool => is_array($options)))
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
        $result = $this->usersService->all($realm, $criteria);

        // then
        $this->assertInstanceOf(UserCollection::class, $result);
        $this->assertSame($userCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('user1', $result->jsonSerialize()[0]->username);
        $this->assertSame('user2', $result->jsonSerialize()[1]->username);
    }

    public function testGet(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '{"id":"user1","username":"user1","firstName":"John","lastName":"Doe"}';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $user = new UserRepresentation();
        $user->id = 'user1';
        $user->username = 'user1';
        $user->firstName = 'John';
        $user->lastName = 'Doe';

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, UserRepresentation::class)
            ->willReturn($user);

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->get($realm, $userId);

        // then
        $this->assertInstanceOf(UserRepresentation::class, $result);
        $this->assertSame($user, $result);
        $this->assertSame('user1', $result->id);
        $this->assertSame('user1', $result->username);
        $this->assertSame('John', $result->firstName);
        $this->assertSame('Doe', $result->lastName);
    }

    public function testCount(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '10';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/count', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->count($realm);

        // then
        $this->assertIsInt($result);
        $this->assertEquals(10, $result);
    }

    public function testCreate(): void
    {
        // given
        $realm = 'test-realm';
        $user = new UserRepresentation();
        $user->username = 'newuser';
        $user->firstName = 'New';
        $user->lastName = 'User';
        $user->email = 'newuser@example.com';

        $responseBody = '';
        $response = $this->createCommandResponse(201, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/users', $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->create($realm, $user);

        // then
        $this->assertTrue($result);
    }

    public function testUpdate(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $user = new UserRepresentation();
        $user->id = 'user1';
        $user->username = 'user1';
        $user->firstName = 'Updated';
        $user->lastName = 'User';
        $user->email = 'updated@example.com';

        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('PUT', 'admin/realms/'.$realm.'/users/'.$userId, $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->update($realm, $userId, $user);

        // then
        $this->assertTrue($result);
    }

    public function testDelete(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/users/'.$userId, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->delete($realm, $userId);

        // then
        $this->assertTrue($result);
    }

    public function testLogout(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with(
                'POST',
                'admin/realms/'.$realm.'/users/'.$userId.'/logout',
                $this->callback(static fn ($options): bool => is_array($options))
            )
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->logout($realm, $userId);

        // then
        $this->assertTrue($result);
    }

    public function testSessions(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '[{"id":"session1","userId":"user1"},{"id":"session2","userId":"user1"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/sessions', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $sessionCollection = new UserSessionCollection();
        $session1 = new UserSessionRepresentation();
        $session1->id = 'session1';
        $session1->userId = 'user1';
        $session2 = new UserSessionRepresentation();
        $session2->id = 'session2';
        $session2->userId = 'user1';
        $sessionCollection->add($session1);
        $sessionCollection->add($session2);

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, UserSessionCollection::class)
            ->willReturn($sessionCollection);

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->sessions($realm, $userId);

        // then
        $this->assertInstanceOf(UserSessionCollection::class, $result);
        $this->assertSame($sessionCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('session1', $result->jsonSerialize()[0]->id);
        $this->assertSame('session2', $result->jsonSerialize()[1]->id);
    }

    public function testOfflineSessions(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $clientId = 'client1';
        $responseBody = '[{"id":"session1","userId":"user1"},{"id":"session2","userId":"user1"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/offline-sessions/'.$clientId, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $sessionCollection = new UserSessionCollection();
        $session1 = new UserSessionRepresentation();
        $session1->id = 'session1';
        $session1->userId = 'user1';
        $session2 = new UserSessionRepresentation();
        $session2->id = 'session2';
        $session2->userId = 'user1';
        $sessionCollection->add($session1);
        $sessionCollection->add($session2);

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, UserSessionCollection::class)
            ->willReturn($sessionCollection);

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->offlineSessions($realm, $userId, $clientId);

        // then
        $this->assertInstanceOf(UserSessionCollection::class, $result);
        $this->assertSame($sessionCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('session1', $result->jsonSerialize()[0]->id);
        $this->assertSame('session2', $result->jsonSerialize()[1]->id);
    }

    public function testGroups(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '[{"id":"group1","name":"group1"},{"id":"group2","name":"group2"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/groups', $this->callback(static fn ($options): bool => is_array($options)))
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
        $result = $this->usersService->groups($realm, $userId);

        // then
        $this->assertInstanceOf(GroupCollection::class, $result);
        $this->assertSame($groupCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('group1', $result->jsonSerialize()[0]->name);
        $this->assertSame('group2', $result->jsonSerialize()[1]->name);
    }

    public function testGroupsCount(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '2';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/groups/count', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->groupsCount($realm, $userId);

        // then
        $this->assertIsInt($result);
        $this->assertEquals(2, $result);
    }

    public function testJoinGroup(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $groupId = 'group1';
        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('PUT', 'admin/realms/'.$realm.'/users/'.$userId.'/groups/'.$groupId, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->joinGroup($realm, $userId, $groupId);

        // then
        $this->assertTrue($result);
    }

    public function testLeaveGroup(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $groupId = 'group1';
        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/users/'.$userId.'/groups/'.$groupId, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->leaveGroup($realm, $userId, $groupId);

        // then
        $this->assertTrue($result);
    }

    public function testRealmRoles(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm', $this->callback(static fn ($options): bool => is_array($options)))
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
        $result = $this->usersService->realmRoles($realm, $userId);

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
        $userId = 'user1';
        $responseBody = '[{"id":"role3","name":"role3"},{"id":"role4","name":"role4"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm/available', $this->callback(static fn ($options): bool => is_array($options)))
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
        $result = $this->usersService->availableRealmRoles($realm, $userId);

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
        $userId = 'user1';
        $role = new RoleRepresentation();
        $role->id = 'role3';
        $role->name = 'role3';

        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm', $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->addRealmRole($realm, $userId, $role);

        // then
        $this->assertTrue($result);
    }

    public function testRemoveRealmRole(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $role = new RoleRepresentation();
        $role->id = 'role1';
        $role->name = 'role1';

        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/realm', $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->removeRealmRole($realm, $userId, $role);

        // then
        $this->assertTrue($result);
    }

    public function testClientRoles(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $userId = 'user1';
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid, $this->callback(static fn ($options): bool => is_array($options)))
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
        $result = $this->usersService->clientRoles($realm, $clientUuid, $userId);

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
        $userId = 'user1';
        $responseBody = '[{"id":"role3","name":"role3"},{"id":"role4","name":"role4"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid.'/available', $this->callback(static fn ($options): bool => is_array($options)))
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
        $result = $this->usersService->availableClientRoles($realm, $clientUuid, $userId);

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
        $userId = 'user1';
        $role = new RoleRepresentation();
        $role->id = 'role3';
        $role->name = 'role3';

        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid, $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->addClientRole($realm, $clientUuid, $userId, $role);

        // then
        $this->assertTrue($result);
    }

    public function testRemoveClientRole(): void
    {
        // given
        $realm = 'test-realm';
        $clientUuid = 'client1';
        $userId = 'user1';
        $role = new RoleRepresentation();
        $role->id = 'role1';
        $role->name = 'role1';

        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/users/'.$userId.'/role-mappings/clients/'.$clientUuid, $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->removeClientRole($realm, $clientUuid, $userId, $role);

        // then
        $this->assertTrue($result);
    }

    public function testGetProfileConfig(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '{"attributes":[{"name":"firstName","displayName":"First name"}]}';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/profile', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $config = new UPConfig();

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, UPConfig::class)
            ->willReturn($config);

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->getProfileConfig($realm);

        // then
        $this->assertInstanceOf(UPConfig::class, $result);
        $this->assertSame($config, $result);
    }

    public function testGetProfileMetadata(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '{"userProfileAttributeMetadata":[{"name":"firstName","displayName":"First name"}]}';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/users/profile/metadata', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $metadata = new UserProfileMetadata();

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, UserProfileMetadata::class)
            ->willReturn($metadata);

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->getProfileMetadata($realm);

        // then
        $this->assertInstanceOf(UserProfileMetadata::class, $result);
        $this->assertSame($metadata, $result);
    }

    public function testResetPassword(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('PUT', 'admin/realms/'.$realm.'/users/'.$userId.'/reset-password', $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->resetPassword($realm, $userId);

        // then
        $this->assertTrue($result);
    }

    public function testSendVerifyEmail(): void
    {
        // given
        $realm = 'test-realm';
        $userId = 'user1';
        $parameters = ['clientId' => 'client1', 'redirectUri' => 'http://example.com'];
        $responseBody = '';
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('PUT', 'admin/realms/'.$realm.'/users/'.$userId.'/send-verify-email', $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

        // when
        $result = $this->usersService->sendVerifyEmail($realm, $userId, $parameters);

        // then
        $this->assertTrue($result);
    }
}
