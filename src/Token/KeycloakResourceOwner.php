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

    public const ROLES_SOURCE_ALL = 'all';
    public const ROLES_SOURCE_AUTHORIZED_PARTY = 'authorized_party';

    /**
     * Creates new resource owner.
     *
     * @param array<string,mixed>    $response    The raw response from the token decoder
     * @param string                 $rolesSource `all`: realm roles and the roles of every client (default);
     *                                            `authorized_party`: only the roles of the client that requested the token (`azp`)
     * @param array<string,string[]> $clientRoles extra roles granted according to the client that requested the token, keyed by client id
     */
    public function __construct(
        array $response = [],
        ?AccessTokenInterface $accessToken = null,
        protected string $rolesSource = self::ROLES_SOURCE_ALL,
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
            return $resource_access[$client_id]['roles'] ?? [];
        }

        // Otherwise, collect all roles from all clients
        return array_reduce(
            $resource_access,
            static fn (array $carry, array $client): array => [
                ...$carry,
                ...$client['roles'] ?? [],
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
        $authorizedParty = $this->getAuthorizedParty();
        $extraRoles = null !== $authorizedParty ? $this->clientRoles[$authorizedParty] ?? [] : [];

        if (null === $client_id && self::ROLES_SOURCE_AUTHORIZED_PARTY === $this->rolesSource) {
            $tokenClientRoles = null !== $authorizedParty ? $this->getClientRoles($authorizedParty) : [];

            return array_values(array_unique([...$tokenClientRoles, ...$extraRoles]));
        }

        return [...$this->getRealmRoles(), ...$this->getClientRoles($client_id), ...$extraRoles];
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
