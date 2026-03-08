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
use Mainick\KeycloakClientBundle\Tests\Service\Support\ExecuteCommandTestHelperTrait;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

class RolesServiceTest extends TestCase
{
    use ExecuteCommandTestHelperTrait;

    private RolesService $rolesService;
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

        $this->rolesService = new RolesService(
            $this->logger,
            $this->keycloakAdminClient
        );

        $reflection = new \ReflectionClass($this->rolesService);
        $serializerProperty = $reflection->getProperty('serializer');
        $serializerProperty->setValue($this->rolesService, $this->serializer);
    }

    public function testAll(): void
    {
        // given
        $realm = 'test-realm';
        $responseBody = '[{"id":"role1","name":"role1"},{"id":"role2","name":"role2"}]';
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles', $this->callback(static function ($options): bool {
                return is_array($options) &&
                       isset($options['headers']['Authorization']) &&
                       $options['headers']['Authorization'] === 'Bearer mock_token';
            }))
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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles?briefRepresentation=true', $this->callback(static fn ($options): bool => is_array($options)))
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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $role = new RoleRepresentation();
        $role->id = 'role1';
        $role->name = 'role1';
        $role->description = 'Test role';

        $this->serializer
            ->expects($this->once())
            ->method('deserialize')
            ->with($responseBody, RoleRepresentation::class)
            ->willReturn($role);

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(201, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('POST', 'admin/realms/'.$realm.'/roles', $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('PUT', 'admin/realms/'.$realm.'/roles/'.$roleName, $this->callback(static function ($options): bool {
                return isset($options['json']);
            }))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(204, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('DELETE', 'admin/realms/'.$realm.'/roles/'.$roleName, $this->callback(static fn ($options): bool => is_array($options)))
            ->willReturn($response);

        $this->serializer
            ->expects($this->never())
            ->method('deserialize');

        $this->logger->expects($this->once())->method('info');

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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/groups', $this->callback(static fn ($options): bool => is_array($options)))
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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/groups?first=0&max=10', $this->callback(static fn ($options): bool => is_array($options)))
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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/users', $this->callback(static fn ($options): bool => is_array($options)))
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
        $response = $this->createCommandResponse(200, $responseBody);

        $this->httpClient
            ->expects($this->once())
            ->method('request')
            ->with('GET', 'admin/realms/'.$realm.'/roles/'.$roleName.'/users?first=0&max=10', $this->callback(static fn ($options): bool => is_array($options)))
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
        $result = $this->rolesService->users($realm, $roleName, $criteria);

        // then
        $this->assertInstanceOf(UserCollection::class, $result);
        $this->assertSame($userCollection, $result);
        $this->assertEquals(2, $result->count());
        $this->assertSame('user1', $result->jsonSerialize()[0]->username);
        $this->assertSame('user2', $result->jsonSerialize()[1]->username);
    }
}
