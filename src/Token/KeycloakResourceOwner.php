<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Interface\ResourceOwnerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface, UserInterface
{
    /**
     * Raw response.
     */
    protected array $response;

    protected ?AccessTokenInterface $accessToken = null;

    /**
     * Creates new resource owner.
     */
    public function __construct(array $response = [], ?AccessTokenInterface $accessToken = null)
    {
        $this->response = $response;
        $this->accessToken = $accessToken;
    }

    public function getAccessToken(): ?AccessTokenInterface
    {
        return $this->accessToken;
    }

    /**
     * Get resource owner id.
     */
    public function getId(): string
    {
        return $this->response['sub'];
    }

    /**
     * Get resource owner email.
     */
    public function getEmail(): ?string
    {
        return $this->response['email'] ?? null;
    }

    /**
     * Get resource owner name.
     */
    public function getName(): ?string
    {
        return $this->response['name'] ?? null;
    }

    /**
     * Get resource owner username.
     */
    public function getUsername(): ?string
    {
        return $this->response['preferred_username'] ?? null;
    }

    /**
     * Get resource owner first name.
     */
    public function getFirstName(): ?string
    {
        return $this->response['given_name'] ?? null;
    }

    /**
     * Get resource owner last name.
     */
    public function getLastName(): ?string
    {
        return $this->response['family_name'] ?? null;
    }

    /**
     * Get realm roles.
     *
     * @return array<string>
     */
    private function getRealmRoles(): array
    {
        return $this->response['realm_access']['roles'] ?? [];
    }

    /**
     * Get client roles.
     *
     * @param string|null $client_id Optional client ID to filter roles
     * @return array<string>
     */
    private function getClientRoles(?string $client_id = null): array
    {
        $resource_access = $this->response['resource_access'] ?? [];

        // If client_id is provided, return only roles for that client
        if ($client_id !== null) {
            return $resource_access[$client_id]['roles'] ?? [];
        }

        // Otherwise, collect all roles from all clients
        return array_reduce(
            $resource_access,
            static fn(array $carry, array $client): array => [
                ...$carry,
                ...($client['roles'] ?? [])
            ],
            []
        );
    }

    /**
     * Get realm and resource owner roles.
     *
     * @return array<string>
     */
    public function getRoles(?string $client_id = null): array
    {
        return [...$this->getRealmRoles(), ...$this->getClientRoles($client_id)];
    }

    /**
     * Get resource owner groups.
     *
     * @return array<string>
     */
    public function getGroups(): array
    {
        return $this->response['groups'] ?? [];
    }

    /**
     * Get resource owner scopes.
     *
     * @return array<string>
     */
    public function getScope(): array
    {
        return explode(' ', $this->response['scope'] ?? '');
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return $this->response;
    }

    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return $this->getUsername();
    }
}
