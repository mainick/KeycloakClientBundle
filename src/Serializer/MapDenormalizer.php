<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Serializer;

use Mainick\KeycloakClientBundle\Representation\Type\Map;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;

final class MapDenormalizer implements DenormalizerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function denormalize(mixed $data, string $type, ?string $format = null, array $context = []): mixed
    {
        if ($data instanceof Map) {
            return $data;
        }

        if (!is_array($data) || empty($data)) {
            return new Map();
        }

        return new Map($data);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return Map::class === $type;
    }

    public function getSupportedTypes(?string $format): array
    {
        return [
            Map::class => true,
        ];
    }
}
