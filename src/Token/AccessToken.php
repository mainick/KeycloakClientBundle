<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Token;

use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;

class AccessToken implements AccessTokenInterface
{
    protected string $accessToken;
    protected int $expires;
    protected string $refreshToken;
    /** @var array<string, mixed> */
    protected array $values = [];

    public function __construct()
    {
    }

    public function getToken(): string
    {
        return $this->accessToken;
    }

    public function setToken(string $token): AccessTokenInterface
    {
        $this->accessToken = $token;

        return $this;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(string $refreshToken): AccessTokenInterface
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    public function getExpires(): ?int
    {
        return $this->expires;
    }

    public function setExpires(int $expires): AccessTokenInterface
    {
        $this->expires = $expires;

        return $this;
    }

    public function hasExpired(): bool
    {
        $expires = $this->getExpires();
        if (null === $expires) {
            throw new \RuntimeException('"expires" is not set on the token');
        }

        return $expires < time();
    }

    /**
     * Returns the token values as an array.
     *
     * @return array<string, mixed>
     */
    public function getValues(): array
    {
        return $this->values;
    }

    /**
     * Sets the token values from an array.
     *
     * @param array<string, mixed> $values
     */
    public function setValues(array $values): AccessTokenInterface
    {
        $this->values = $values;

        return $this;
    }

    public function __toString(): string
    {
        return (string) $this->getToken();
    }

    /**
     * Returns the token values as an array.
     *
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        $parameters = $this->values;
        if ($this->accessToken) {
            $parameters['access_token'] = $this->accessToken;
        }
        if ($this->refreshToken) {
            $parameters['refresh_token'] = $this->refreshToken;
        }
        if ($this->expires) {
            $parameters['expires'] = $this->expires;
        }

        return $parameters;
    }
}
