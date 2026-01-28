<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Serializer;

use Mainick\KeycloakClientBundle\Representation\Collection\Collection;
use Mainick\KeycloakClientBundle\Representation\Representation;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;

final readonly class RepresentationDenormalizer implements DenormalizerInterface
{
    public function __construct(private DenormalizerInterface $denormalizer)
    {
    }

    public function denormalize(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = [],
    ): mixed {
        if (!is_array($data)) {
            throw new \InvalidArgumentException('Data expected to be an array for representation denormalization');
        }

        $representation = new $type();
        if (!$representation instanceof Representation) {
            throw new \InvalidArgumentException(sprintf('Type %s is not a valid Representation class.', $type));
        }

        $reflectionClass = new \ReflectionClass($type);
        $constructorParams = [];
        $constructor = $reflectionClass->getConstructor();
        if (null !== $constructor) {
            foreach ($constructor->getParameters() as $param) {
                $paramName = $param->getName();
                if (array_key_exists($paramName, $data)) {
                    $paramValue = $data[$paramName];
                    $paramType = $param->getType();

                    if (
                        null !== $paramType
                        && $paramType instanceof \ReflectionNamedType
                        && !$paramType->isBuiltin()
                        && is_array($paramValue)
                    ) {
                        $paramTypeName = $paramType->getName();

                        // This is the recursive part
                        if (
                            class_exists($paramTypeName)
                            && (is_subclass_of(
                                $paramTypeName,
                                Collection::class,
                            )
                                || is_subclass_of(
                                    $paramTypeName,
                                    Representation::class,
                                ))
                        ) {
                            $paramValue = $this->denormalizer->denormalize(
                                $paramValue,
                                $paramTypeName,
                                $format,
                                $context,
                            );
                        }
                    }

                    $constructorParams[$paramName] = $paramValue;
                }
                else {
                    $constructorParams[
                        $paramName
                    ] = $param->isDefaultValueAvailable()
                        ? $param->getDefaultValue()
                        : null;
                }
            }

            $representation = $reflectionClass->newInstanceArgs(
                $constructorParams,
            );
        }
        else {
            $representation = $type::from($data);
        }

        return $representation;
    }

    public function supportsDenormalization(
        mixed $data,
        string $type,
        ?string $format = null,
        array $context = [],
    ): bool {
        return is_array($data)
            && class_exists($type)
            && is_subclass_of($type, Representation::class);
    }

    public function getSupportedTypes(?string $format): array
    {
        return [
            Representation::class => true,
        ];
    }
}
