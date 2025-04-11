<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Serializer;

use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Mapping\Factory\ClassMetadataFactory;
use Symfony\Component\Serializer\Mapping\Loader\AttributeLoader;
use Symfony\Component\Serializer\NameConverter\MetadataAwareNameConverter;
use Symfony\Component\Serializer\Normalizer\ArrayDenormalizer;
use Symfony\Component\Serializer\Normalizer\BackedEnumNormalizer;
use Symfony\Component\Serializer\Normalizer\PropertyNormalizer;
use Symfony\Component\Serializer\Serializer as SymfonySerializer;

class Serializer
{
    private SymfonySerializer $serializer;

    public function __construct(
        private ?string $keycloakVersion = null,
    ) {
        $classMetadataFactory = new ClassMetadataFactory(new AttributeLoader());
        $metadataAwareNameConverter = new MetadataAwareNameConverter($classMetadataFactory);
        $propertyNormalizer = new PropertyNormalizer(
            classMetadataFactory: $classMetadataFactory,
            nameConverter: $metadataAwareNameConverter,
            defaultContext: [
                PropertyNormalizer::NORMALIZE_VISIBILITY => PropertyNormalizer::NORMALIZE_PUBLIC
            ]
        );

        $this->serializer = new SymfonySerializer(
            [
                new BackedEnumNormalizer(),
                new ArrayDenormalizer(),
                new CollectionDenormalizer($propertyNormalizer),
                new MapNormalizer(),
                new MapDenormalizer(),
                new AttributeNormalizer($propertyNormalizer, $this->keycloakVersion),
                $propertyNormalizer,
            ],
            [
                new JsonEncoder(),
            ],
            [
                'json_encode_options' => JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
            ]
        );
    }

    public function serialize(mixed $data): ?string
    {
        return null === $data ? null : $this->serializer->serialize($data, JsonEncoder::FORMAT);
    }

    public function deserialize(mixed $data, string $type): mixed
    {
        return $this->serializer->deserialize($data, $type, JsonEncoder::FORMAT);
    }
}
