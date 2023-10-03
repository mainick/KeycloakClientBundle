<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Interface;

interface ResourceOwnerInterface
{
    /**
     * Returns the identifier of the authorized resource owner.
     */
    public function getId(): string;

    /**
     * Returns the email of the authorized resource owner.
     */
    public function getEmail(): ?string;

    /**
     * Returns the name of the authorized resource owner.
     */
    public function getName(): ?string;

    /**
     * Returns the username of the authorized resource owner.
     */
    public function getUsername(): ?string;

    /**
     * Returns the first name of the authorized resource owner.
     */
    public function getFirstName(): ?string;

    /**
     * Returns the last name of the authorized resource owner.
     */
    public function getLastName(): ?string;

    /**
     * Return all of the owner details available as an array.
     */
    public function toArray(): array;
}
