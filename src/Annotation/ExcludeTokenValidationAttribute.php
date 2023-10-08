<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Annotation;

#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD)]
final class ExcludeTokenValidationAttribute
{
}
