<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Mainick\KeycloakClientBundle\DTO\OrganizationRepresentationDTO;
use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Interface\ResourceOwnerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class KeycloakResourceOwner implements ResourceOwnerInterface, UserInterface
{
    /**
     * Raw response.
     *
     * @param array<string,mixed> $response
     */
    protected array $response;

    protected ?AccessTokenInterface $accessToken = null;

    /**
     * Creates new resource owner.
     *
     * @param array<string,mixed>    $response    The raw response from the token decoder
     * @param array<string,string[]> $clientRoles extra roles granted, with {@see RolesSourceEnum::AUTHORIZED_PARTY},
     *                                            according to the client that requested the token, keyed by client id
     */
    public function __construct(
        array $response = [],
        ?AccessTokenInterface $accessToken = null,
        protected RolesSourceEnum $rolesSource = RolesSourceEnum::ALL,
        protected array $clientRoles = [],
    ) {
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
     *
     * @return array<string>
     */
    private function getClientRoles(?string $client_id = null): array
    {
        $resource_access = $this->response['resource_access'] ?? [];

        // If client_id is provided, return only roles for that client
        if (null !== $client_id) {
            $roles = $resource_access[$client_id]['roles'] ?? [];

            return is_array($roles) ? $roles : [];
        }

        // Otherwise, collect all roles from all clients
        return array_reduce(
            $resource_access,
            static fn (array $carry, array $client): array => [
                ...$carry,
                ...(is_array($client['roles'] ?? null) ? $client['roles'] : []),
            ],
            []
        );
    }

    /**
     * Get realm and resource owner roles.
     *
     * With an explicit client id: realm roles plus that client's roles. Without it, it depends on the roles
     * source: {@see RolesSourceEnum::ALL} returns realm roles plus every client's roles,
     * {@see RolesSourceEnum::AUTHORIZED_PARTY} only the roles of the `azp` client plus its configured client roles.
     *
     * @return array<string>
     */
    public function getRoles(?string $client_id = null): array
    {
        if (null !== $client_id || RolesSourceEnum::ALL === $this->rolesSource) {
            return [...$this->getRealmRoles(), ...$this->getClientRoles($client_id)];
        }

        $authorizedParty = $this->getAuthorizedParty();
        if (null === $authorizedParty) {
            return [];
        }

        return array_values(array_unique([
            ...$this->getClientRoles($authorizedParty),
            ...$this->clientRoles[$authorizedParty] ?? [],
        ]));
    }

    /**
     * Get the client that requested the token (`azp` claim).
     */
    public function getAuthorizedParty(): ?string
    {
        $azp = $this->response['azp'] ?? null;

        return is_string($azp) && '' !== $azp ? $azp : null;
    }

    /**
     * Get the organizations the resource owner belongs to (`organization` claim).
     *
     * @return OrganizationRepresentationDTO[]
     */
    public function getOrganizations(): array
    {
        return OrganizationRepresentationDTO::listFromClaim($this->response['organization'] ?? null) ?? [];
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
     * Get resource owner attributes.
     *
     * @return array<string,mixed>
     */
    public function getAttributes(): array
    {
        return $this->response['attributes'] ?? [];
    }

    /**
     * Get a single resource owner attribute, or null when it is missing.
     */
    public function getAttribute(string $name): ?string
    {
        return $this->getAttributes()[$name] ?? null;
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

    #[\Deprecated]
    public function eraseCredentials(): void
    {
    }

    public function getUserIdentifier(): string
    {
        return $this->getUsername();
    }
}
