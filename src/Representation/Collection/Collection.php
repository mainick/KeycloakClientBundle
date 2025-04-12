<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\Representation;

/**
 * @template T of Representation
 *
 * @implements \IteratorAggregate<int, T>
 */
abstract class Collection implements \Countable, \IteratorAggregate, \JsonSerializable
{
    /**
     * @var array<array-key, T>
     */
    protected array $items = [];

    /**
     * @param iterable<T> $items
     */
    public function __construct(iterable $items = [])
    {
        foreach ($items as $item) {
            $this->add($item);
        }
    }

    public function count(): int
    {
        return count($this->items);
    }

    /**
     * @return \ArrayIterator<int, T>
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->items);
    }

    /**
     * @return array<array-key, T>
     */
    public function jsonSerialize(): array
    {
        return $this->items;
    }

    /**
     * @param T $representation
     */
    public function add(Representation $representation): void
    {
        $expectedClass = static::getRepresentationClass();
        if (!$representation instanceof $expectedClass) {
            throw new \InvalidArgumentException(sprintf(
                '%s expects items to be %s representation, %s given',
                (new \ReflectionClass(static::class))->getShortName(),
                (new \ReflectionClass($expectedClass))->getShortName(),
                (new \ReflectionClass($representation))->getShortName()
            ));
        }

        $this->items[] = $representation;
    }

    /**
     * @return T|null
     */
    public function first(): ?Representation
    {
        return $this->items[0] ?? null;
    }

    /**
     * @return array<array-key, T>
     */
    public function all(): array
    {
        return $this->items;
    }

    /**
     * @return class-string<T>
     */
    abstract public static function getRepresentationClass(): string;
}
