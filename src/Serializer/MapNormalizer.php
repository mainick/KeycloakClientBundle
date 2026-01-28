<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Serializer;

use Mainick\KeycloakClientBundle\Representation\Type\Map;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

final class MapNormalizer implements NormalizerInterface
{
    /**
     * @param array<string, mixed> $context
     *
     * @return \ArrayObject<string, mixed>
     */
    public function normalize(
        mixed $data,
        ?string $format = null,
        array $context = [],
    ): \ArrayObject {
        if (!$data instanceof Map) {
            throw new \InvalidArgumentException('Data must be an instance of Map.');
        }

        return new \ArrayObject($data->jsonSerialize());
    }

    /**
     * @param array<string, mixed> $context
     */
    public function supportsNormalization(
        mixed $data,
        ?string $format = null,
        array $context = [],
    ): bool {
        return $data instanceof Map;
    }

    public function getSupportedTypes(?string $format): array
    {
        return [
            Map::class => true,
        ];
    }
}
