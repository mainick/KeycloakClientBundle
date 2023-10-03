KeycloakClientBundle
====================

[![Latest Version](https://img.shields.io/github/release/mainick/KeycloakClientBundle.svg?style=flat-square)](https://github.com/mainick/KeycloakClientBundle/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Total Downloads](https://img.shields.io/packagist/dt/mainick/keycloak-client-bundle.svg?style=flat-square)](https://packagist.org/packages/mainick/keycloak-client-bundle)

This package provides a simple integration of the Keycloak PHP client in Symfony. 
It provides a service to get the Keycloak client and a listener to token validator the user.

## Installation

To install, use composer:

```
composer require mainick/keycloak-client-bundle
```

Then, enable the bundle by adding it to the list of registered bundles
in the `config/bundles.php` file of your project:

```php
// config/bundles.php

return [
    // ...
    Mainick\KeycloakClientBundle\MainickKeycloakClientBundle::class => ['all' => true],
];
```

## Configuration

The bundle provides a default configuration for the Keycloak client.
You can override it by adding the following configuration to
your `config/packages/mainick_keycloak_client.yaml` file:

```yaml
mainick_keycloak_client:
  keycloak:
    verify_ssl: <your-ssl-required>
    base_url: <your-base-server-url> # Keycloak server URL
    realm: <your-realm> # Keycloak realm name
    client_id: <your-client-id> # Keycloak client id
    client_secret: <your-client-secret> # Keycloak client secret
    redirect_uri: <your-redirect-uri>
    encryption_algorithm: <your-algorithm>
    encryption_key: <your-public-key>
    encryption_key_path: <your-public-key-path>
    version: <your-version-keycloak>
```

## Usage

### Get the Keycloak client

You can get the Keycloak client by injecting the `Mainick\KeycloakClientBundle\Interface\IamClientInterface`
interface in your controller or service.

To use it, you need to add the following configuration
to your `config/services.yaml` file:

```yaml
services:
    Mainick\KeycloakClientBundle\Interface\IamClientInterface:
        alias: Mainick\KeycloakClientBundle\Provider\KeycloakClient
```

Then, you can use it in your controller or service:

```php
<?php

declare(strict_types=1);

namespace App\Service;

use Mainick\KeycloakClientBundle\Interface\IamClientInterface;

class IamService
{
    public function __construct(
        private IamClientInterface $iamClient
    ) {
    }
}
```

### Authenticate the user

```php
...

    public function authenticate(string $username, string $password): never
    {
        $accessToken = $this->iamClient->authenticate($username, $password);

        // Do something with the access token
    }

...
```

### Refreshing a Token

```php
...

    public function refreshToken(AccessTokenInterface $token): ?AccessTokenInterface
    {
        return $this->iamClient->refreshToken($token);
    }

...
```

### User info

```php
...

    public function userInfo(AccessTokenInterface $token): ?UserRepresentationDTO
    {
        return $this->iamClient->userInfo($token);
    }

...
```

### Token validator the user

The bundle provides a listener to authenticate the user. To use it, you need to add the following configuration
to your `config/services.yaml` file:

```yaml
services:
    Mainick\KeycloakClientBundle\EventSubscriber\TokenAuthListener:
        tags:
          - { name: kernel.event_listener, event: kernel.request, method: checkValidToken, priority: 0 }
```

## Running the Tests

Install the [Composer](http://getcomposer.org/) dependencies:

```bash
git clone https://github.com/mainick/KeycloakClientBundle.git
cd KeycloakClientBundle
composer update
```

Then run the test suite:

```bash
composer test:unit
```

## Credits

- [Maico Orazio](https://github.com/mainick)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

<!-- ## Contributing -->
<!-- Please see [Contributing](CONTRIBUTING.md) for details. -->
<!-- ## Changelog -->
<!-- Please see [Changelog](CHANGELOG.md) for details. -->
