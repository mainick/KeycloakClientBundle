<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Serializer;

use Mainick\KeycloakClientBundle\Representation\Collection\RealmCollection;
use Mainick\KeycloakClientBundle\Representation\RealmRepresentation;
use Mainick\KeycloakClientBundle\Serializer\CollectionDenormalizer;
use Mainick\KeycloakClientBundle\Serializer\RepresentationDenormalizer;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Mapping\Factory\ClassMetadataFactory;
use Symfony\Component\Serializer\Mapping\Loader\AttributeLoader;
use Symfony\Component\Serializer\NameConverter\MetadataAwareNameConverter;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Serializer\Normalizer\PropertyNormalizer;

class CollectionDenormalizerTest extends TestCase
{
    public function testDenormalizeRealmCollection(): void
    {
        // given
        $innerDenormalizer = $this->createMock(DenormalizerInterface::class);
        $denormalizer = new CollectionDenormalizer($innerDenormalizer);

        $realmData = [
            [
                'id' => '1',
                'realm' => 'master',
                'displayName' => 'Master Realm',
                'enabled' => true
            ],
            [
                'id' => '2',
                'realm' => 'test',
                'displayName' => 'Test Realm',
                'enabled' => false
            ]
        ];

        $realm1 = new RealmRepresentation(
            id: '1',
            realm: 'master',
            displayName: 'Master Realm',
            enabled: true
        );

        $realm2 = new RealmRepresentation(
            id: '2',
            realm: 'test',
            displayName: 'Test Realm',
            enabled: false
        );

        $innerDenormalizer->expects($this->exactly(2))
            ->method('denormalize')
            ->willReturnCallback(function ($data, $type, $format, $context) use ($realm1, $realm2) {
                if ($data['id'] === '1') {
                    return $realm1;
                }
                return $realm2;
            });

        // when
        $result = $denormalizer->denormalize($realmData, RealmCollection::class, JsonEncoder::FORMAT);

        // then
        $this->assertInstanceOf(RealmCollection::class, $result);
        $this->assertCount(2, $result);

        $items = $result->all();
        $this->assertSame($realm1, $items[0]);
        $this->assertSame($realm2, $items[1]);
    }

    public function testDenormalizeRealmCollectionWithRealDenormalizer(): void
    {
        // Configurazione di un denormalizzatore reale
        $classMetadataFactory = new ClassMetadataFactory(new AttributeLoader());
        $metadataAwareNameConverter = new MetadataAwareNameConverter($classMetadataFactory);
        $propertyNormalizer = new PropertyNormalizer(
            classMetadataFactory: $classMetadataFactory,
            nameConverter: $metadataAwareNameConverter,
            defaultContext: [
                PropertyNormalizer::NORMALIZE_VISIBILITY => PropertyNormalizer::NORMALIZE_PROTECTED,
            ]
        );

        // Utilizziamo RepresentationDenormalizer per gestire correttamente i costruttori delle rappresentazioni
        $representationDenormalizer = new RepresentationDenormalizer($propertyNormalizer);

        // Istanza del denormalizzatore da testare
        $denormalizer = new CollectionDenormalizer($representationDenormalizer);

        // Dati di test
        $realmData = [
            [
                'id' => '1',
                'realm' => 'master',
                'displayName' => 'Master Realm',
                'enabled' => true
            ],
            [
                'id' => '2',
                'realm' => 'test',
                'displayName' => 'Test Realm',
                'enabled' => false
            ]
        ];

        // Esecuzione
        $result = $denormalizer->denormalize($realmData, RealmCollection::class, JsonEncoder::FORMAT);

        // Verifiche
        $this->assertInstanceOf(RealmCollection::class, $result);
        $this->assertCount(2, $result);

        $items = $result->all();

        // Verifica delle proprietà degli oggetti denormalizzati
        $this->assertInstanceOf(RealmRepresentation::class, $items[0]);
        $this->assertEquals('1', $items[0]->id);
        $this->assertEquals('master', $items[0]->realm);
        $this->assertEquals('Master Realm', $items[0]->displayName);
        $this->assertTrue($items[0]->enabled);

        $this->assertInstanceOf(RealmRepresentation::class, $items[1]);
        $this->assertEquals('2', $items[1]->id);
        $this->assertEquals('test', $items[1]->realm);
        $this->assertEquals('Test Realm', $items[1]->displayName);
        $this->assertFalse($items[1]->enabled);
    }
}
