<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

final readonly class Criteria
{
    /**
     * @param array<string, mixed> $criteria
     */
    public function __construct(
        private array $criteria = []
    ) {
    }

    public function jsonSerialize(): array
    {
        return array_filter(
            array_map(
                static function ($value) {
                    if (is_bool($value)) {
                        return $value ? 'true' : 'false';
                    }

                    if ($value instanceof \DateTimeInterface) {
                        return $value->format('Y-m-d');
                    }

                    if ($value instanceof \Stringable) {
                        return $value->__toString();
                    }

                    return $value;
                },
                $this->criteria
            ),
            static fn($value) => null !== $value
        );
    }
}
