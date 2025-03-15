<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Exception\PropertyDoesNotExistException;
use PhpParser\JsonDecoder;

abstract class Representation implements \JsonSerializable
{
    abstract public function __construct();

    /**
     * @param array $properties
     * @return static
     * @throws PropertyDoesNotExistException
     */
    final public static function from(array $properties): static
    {
        $representation = new static();
        foreach ($properties as $property => $value) {
            $representation = $representation->withProperty($property, $value);
        }

        return $representation;
    }

    /**
     * @param string $json
     * @return static
     * @throws PropertyDoesNotExistException
     */
    public static function fromJson(string $json): static
    {
        return static::from((new JsonDecoder())->decode($json));
    }

    final public function jsonSerialize(): array
    {
        $serializable = [];
        $reflectedClass = (new \ReflectionClass($this));
        $properties = $reflectedClass->getProperties(\ReflectionProperty::IS_PUBLIC);
        foreach ($properties as $property) {
            $serializable[$property->getName()] = ($property->getValue($this) instanceof \JsonSerializable)
                ? $property->getValue($this)->jsonSerialize()
                : $property->getValue($this);
        }

        return $serializable;
    }

    /**
     * @throws PropertyDoesNotExistException
     */
    private function withProperty(string $property, mixed $value): static
    {
        if (!property_exists(static::class, $property)) {
            throw new PropertyDoesNotExistException(sprintf('Property "%s" does not exist in %s.', $property, static::class));
        }

        $representation = clone $this;
        $representation->$property = $value;

        return $representation;
    }
}
