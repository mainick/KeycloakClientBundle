<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Serializer;

use Mainick\KeycloakClientBundle\Annotation\Since;
use Mainick\KeycloakClientBundle\Annotation\Until;
use Mainick\KeycloakClientBundle\Representation\Representation;
use Symfony\Component\Serializer\Normalizer\NormalizerInterface;

final class AttributeNormalizer implements NormalizerInterface
{
    /** @var array<class-string<Representation>, array<string, array{since?: string, until?: string}>> $filteredProperties */
    private array $filteredProperties = [];

    public function __construct(
        private readonly NormalizerInterface $normalizer,
        private readonly ?string $keycloakVersion = null,
    ) {
    }

    /**
     * @inheritDoc
     * @param array<string, mixed> $context
     */
    public function normalize(mixed $data, ?string $format = null, array $context = []): array|string|int|float|bool|\ArrayObject|null
    {
        $properties = $this->normalizer->normalize($data, $format, $context);
        if (!$this->keycloakVersion) {
            return $properties;
        }

        foreach ($this->getFilteredProperties($data) as $property => $versions) {
            if (array_key_exists('since', $versions) && version_compare($this->keycloakVersion, $versions['since']) < 0) {
                unset($properties[$property]);
            }

            if (array_key_exists('until', $versions) && version_compare($this->keycloakVersion, $versions['until']) > 0) {
                unset($properties[$property]);
            }
        }

        return $properties;
    }

    /**
     * @inheritDoc
     * @param array<string, mixed> $context
     */
    public function supportsNormalization(mixed $data, ?string $format = null, array $context = []): bool
    {
        return $data instanceof Representation;
    }

    /**
     * @inheritDoc
     */
    public function getSupportedTypes(?string $format): array
    {
        return [
            Representation::class => true,
        ];
    }

    private function getFilteredProperties(Representation $representation): array
    {
        if (array_key_exists($representation::class, $this->filteredProperties)) {
            return $this->filteredProperties[$representation::class];
        }

        $filteredProperties = [];
        $properties = (new \ReflectionClass($representation))->getProperties();
        foreach ($properties as $property) {
            $sinceAttribute = $property->getAttributes(Since::class);
            foreach ($sinceAttribute as $since) {
                $filteredProperties[$property->getName()]['since'] = $since->getArguments()['version'];
            }

            $untilAttribute = $property->getAttributes(Until::class);
            foreach ($untilAttribute as $until) {
                $filteredProperties[$property->getName()]['until'] = $until->getArguments()['version'];
            }
        }

        $this->filteredProperties[$representation::class] = $filteredProperties;

        return $filteredProperties;
    }
}
