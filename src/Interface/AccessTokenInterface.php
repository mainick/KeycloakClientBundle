<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Interface;

interface AccessTokenInterface extends \JsonSerializable
{
    /**
     * Returns the access token string of this instance.
     */
    public function getToken(): string;

    /**
     * Sets the access token string of this instance.
     */
    public function setToken(string $token): self;

    /**
     * Returns the refresh token, if defined.
     */
    public function getRefreshToken(): ?string;

    /**
     * Sets the refresh token string of this instance.
     */
    public function setRefreshToken(string $refreshToken): self;

    /**
     * Returns the expiration timestamp in seconds, if defined.
     */
    public function getExpires(): ?int;

    /**
     * Sets the expiration timestamp in seconds of this instance.
     */
    public function setExpires(int $expires): self;

    /**
     * Checks if this token has expired.
     *
     * @return bool true if the token has expired, false otherwise
     *
     * @throws \RuntimeException if 'expires' is not set on the token
     */
    public function hasExpired(): bool;

    /**
     * Returns additional vendor values stored in the token.
     */
    public function getValues(): array;

    /**
     * Sets additional vendor values stored in the token.
     */
    public function setValues(array $values): self;

    /**
     * Returns a string representation of the access token.
     */
    public function __toString(): string;

    /**
     * Returns an array of parameters to serialize when this is serialized with
     * json_encode().
     */
    public function jsonSerialize(): array;
}
