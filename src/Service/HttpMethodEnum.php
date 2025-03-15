<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

enum HttpMethodEnum: string
{
    case GET = 'GET';
    case POST = 'POST';
    case PUT = 'PUT';
    case DELETE = 'DELETE';
}
