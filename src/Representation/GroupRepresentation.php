<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Annotation\Since;
use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Representation;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class GroupRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $name = null,
        public ?string $path = null,
        #[Since('23.0.0')]
        public ?string $parentId = null,
        #[Since('23.0.0')]
        public ?int $subGroupCount = null,
        public ?GroupCollection $subGroups = null,
        public ?Map $attributes = null,
        /** @var string[]|null */
        public ?array $realmRoles = null,
        public ?Map $clientRoles = null,
        public ?Map $access = null
    )
    {
    }
}
