<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Tests\Service\Support;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

trait ExecuteCommandTestHelperTrait
{
    protected function createCommandResponse(int $statusCode, string $responseBody = ''): ResponseInterface
    {
        $stream = $this->createStub(StreamInterface::class);
        $stream->method('getContents')->willReturn($responseBody);

        $response = $this->createStub(ResponseInterface::class);
        $response->method('getStatusCode')->willReturn($statusCode);
        $response->method('getBody')->willReturn($stream);

        return $response;
    }
}

