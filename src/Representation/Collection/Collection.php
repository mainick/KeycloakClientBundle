<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation\Collection;

use Mainick\KeycloakClientBundle\Representation\Representation;

abstract class Collection implements \Countable, \IteratorAggregate, \JsonSerializable
{
    /**
     * @var array<array-key, mixed>
     */
    protected array $items = [];

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

    public function getIterator(): \Traversable
    {
        return new \ArrayIterator($this->items);
    }

    /**
     * @return array<array-key, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->items;
    }

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
     * @return Representation|null
     */
    public function first(): ?Representation
    {
        return $this->items[0] ?? null;
    }

    /**
     * @return array<array-key, mixed>
     */
    public function all(): array
    {
        return $this->items;
    }

    /**
     * @return string
     */
    abstract public static function getRepresentationClass(): string;
}
