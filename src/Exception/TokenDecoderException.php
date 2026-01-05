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

    public static function forSignatureValidationFailure(\Exception $e): self
    {
        return new self('Signature validation failed', $e);
    }

    public static function forExpiration(\Exception $e): self
    {
        return new self('Token has expired', $e);
    }

    public static function forIssuerMismatch(\Exception $e): self
    {
        return new self('Issuer mismatch', $e);
    }

    public static function forAudienceMismatch(\Exception $e): self
    {
        return new self('Audience mismatch', $e);
    }

    public static function forInvalidToken(\Exception $e): self
    {
        return new self('Invalid token', $e);
    }

    public static function forInvalidConfiguration(string $message, ?\Exception $e = null): self
    {
        return new self($message, $e ?? new \Exception($message));
    }

    public static function forJwksError(string $message, \Exception $e): self
    {
        return new self('JWKS error: ' . $message, $e);
    }

    public static function forDecodingError(string $message, \Exception $e): self
    {
        return new self('Token decoding error: ' . $message, $e);
    }

    public static function forSecurityViolation(string $message, ?\Exception $e = null): self
    {
        return new self('Security violation: ' . $message, $e ?? new \Exception($message));
    }
}
