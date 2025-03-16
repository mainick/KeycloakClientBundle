<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Serializer;

use Mainick\KeycloakClientBundle\Representation\Type\Map;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;

final class MapDenormalizer implements DenormalizerInterface
{

    /**
     * @inheritDoc
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
     * @inheritDoc
     * @param array<string, mixed> $context
     */
    public function supportsDenormalization(mixed $data, string $type, ?string $format = null, array $context = []): bool
    {
        return $type === Map::class;
    }

    /**
     * @inheritDoc
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            Map::class => true
        ];
    }
}
