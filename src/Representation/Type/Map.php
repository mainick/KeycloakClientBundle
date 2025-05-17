<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Type;

use Traversable;

/**
 * @template T
 *
 * @implements \JsonSerializable<T>
 */
class Map extends Type implements \Countable, \IteratorAggregate
{
    /**
     * @param array<string, T> $data
     */
    public function __construct(
        private array $data = []
    ) {
    }

    /**
     * @return \ArrayIterator<string, T>
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->data);
    }

    public function count(): int
    {
        return count($this->data);
    }

    public function jsonSerialize(): object
    {
        return (object) $this->data;
    }

    public function contains(string $key): bool
    {
        return array_key_exists($key, $this->data);
    }

    /**
     * @return T
     */
    public function get(string $key): mixed
    {
        if (!$this->contains($key)) {
            throw new \InvalidArgumentException(sprintf('Key "%s" does not exist.', $key));
        }

        return $this->data[$key];
    }

    public function with(string $key, mixed $value): self
    {
        $clone = clone $this;
        $clone->data[$key] = $value;

        return $clone;
    }

    public function without(string $key): self
    {
        $clone = clone $this;
        unset($clone->data[$key]);

        return $clone;
    }

    /**
     * @return array<string, T>
     */
    public function getMap(): array
    {
        return $this->data;
    }
}
