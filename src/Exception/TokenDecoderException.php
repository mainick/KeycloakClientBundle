<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Exception;

class TokenDecoderException extends \Exception
{
    private const CODE = 500;

    public function __construct(string $string, \Exception $e)
    {
        parent::__construct($string, self::CODE, $e);
    }
}
