<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Serializer;

use Mainick\KeycloakClientBundle\Representation\Type\Map;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

final class MapNormalizer implements NormalizerInterface
{

    /**
     * @inheritDoc
     * @param array<string, mixed> $context
     */
    public function normalize(mixed $data, ?string $format = null, array $context = []): \ArrayObject
    {
        if (!$data instanceof Map) {
            throw new \InvalidArgumentException('Data must be an instance of Map.');
        }

        return new \ArrayObject($data->jsonSerialize());
    }

    /**
     * @inheritDoc
     * @param array<string, mixed> $context
     */
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof Map;
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
