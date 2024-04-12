<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Mainick\KeycloakClientBundle\Interface\ResourceOwnerInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface
{
    /**
     * Raw response.
     */
    protected array $response;

    /**
     * Creates new resource owner.
     */
    public function __construct(array $response = [])
    {
        $this->response = $response;
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
    private function getRealRoles(): ?array
    {
        return $this->response['realm_access']['roles'] ?? null;
    }

    /**
     * Get client roles.
     *
     * @return array<string>|null
     */
    private function getClientRoles(?string $client = null): ?array
    {
        $roles = [];

        if (isset($this->response['resource_access'])) {
            foreach ($this->response['resource_access'] as $client_rif) {
                if (isset($client_rif['roles'])) {
                    $roles = [...$roles, ...$client_rif['roles']];
                }
            }
        }

        if (!is_null($client) && isset($this->response['azp']) && $client === $this->response['azp']) {
            $roles = $this->response['resource_access'][$client]['roles'] ?? [];
        }

        return $roles;
    }

    /**
     * Get realm and resource owner roles.
     *
     * @return array<string>
     */
    public function getRoles(?string $client_id = null): array
    {
        $roles = $this->getRealRoles();

        return [...$roles, ...$this->getClientRoles($client_id)];
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
}
