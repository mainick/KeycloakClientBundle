KeycloakClientBundle
====================

[![Latest Version](https://img.shields.io/github/release/mainick/KeycloakClientBundle.svg?style=flat-square)](https://github.com/mainick/KeycloakClientBundle/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Total Downloads](https://img.shields.io/packagist/dt/mainick/keycloak-client-bundle.svg?style=flat-square)](https://packagist.org/packages/mainick/keycloak-client-bundle)

The `KeycloakClientBundle` bundle is a wrapper for the `stevenmaguire/oauth2-keycloak` package,
designed to simplify Keycloak integration into your application in Symfony and provide additional functionality
for token management and user information access.
It also includes a listener to verify the token on every request.

## Installation

You can install this package using [Composer](http://getcomposer.org/):

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

Perform the desired operations, such as retrieving additional user claims, assigned roles, associated groups, etc.


```php
// authenticate the user
$accessToken = $this->iamClient->authenticate($username, $password);

// verify and introspect the token
$userRepresentation = $this->iamClient->verifyToken($accessToken);
echo $userRepresentation->id; // id
echo $userRepresentation->username; // username
echo $userRepresentation->email; // email
echo $userRepresentation->firstName; // first name
echo $userRepresentation->lastName; // last name
echo $userRepresentation->name; // full name
echo $userRepresentation->groups; // all groups assigned to the user
echo $userRepresentation->realmRoles; // realm roles assigned to the user
echo $userRepresentation->clientRoles; // client roles assigned to the user
echo $userRepresentation->applicationRoles; // specific client roles assigned to the user
echo $userRepresentation->attributes; // additional user attributes

// refresh the token
$accessToken = $this->iamClient->refreshToken($accessToken);

// get user info
$userInfo = $this->iamClient->userInfo($accessToken);
echo $userInfo->id; // id
echo $userInfo->username; // username
echo $userInfo->email; // email
echo $userInfo->firstName; // first name
echo $userInfo->lastName; // last name
echo $userInfo->name; // full name
echo $userInfo->groups; // all groups assigned to the user
echo $userInfo->realmRoles; // realm roles assigned to the user
echo $userInfo->clientRoles; // client roles assigned to the user
echo $userInfo->applicationRoles; // specific client roles assigned to the user
echo $userInfo->attributes; // additional user attributes

// has role
$hasRole = $this->iamClient->hasRole($accessToken, $roleName);

// has any role
$hasAnyRole = $this->iamClient->hasAnyRole($accessToken, $roleNames);

// has all roles
$hasAllRoles = $this->iamClient->hasAllRoles($accessToken, $roleNames);

// has group
$hasGroup = $this->iamClient->hasGroup($accessToken, $groupName);

// has any group
$hasAnyGroup = $this->iamClient->hasAnyGroup($accessToken, $groupNames);

// has all groups
$hasAllGroups = $this->iamClient->hasAllGroups($accessToken, $groupNames);

// has scope
$hasScope = $this->iamClient->hasScope($accessToken, $scopeName);

// has any scope
$hasAnyScope = $this->iamClient->hasAnyScope($accessToken, $scopeNames);

// has all scopes
$hasAllScopes = $this->iamClient->hasAllScopes($accessToken, $scopeNames);
```

### Token Verification Listener

The KeycloakClientBundle includes a built-in listener that verifies the token on every request,
ensuring the security and validity of your Keycloak integration.
This listener seamlessly handles token validation, allowing you to focus on your application's logic.

To use it, you need to add the following configuration to your `config/services.yaml` file:

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
composer test
```

## Author

- [Maico Orazio](https://github.com/mainick)

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.


## Contributing

We welcome your contributions! If you wish to enhance this package or have found a bug,
feel free to create a pull request or report an issue in the [issue tracker](https://github.com/mainick/KeycloakClientBundle/issues).

<!-- ## Contributing -->
<!-- Please see [Contributing](CONTRIBUTING.md) for details. -->

<!-- ## Acknowledgments -->
<!-- A big thank you to [Steven Maguire](https://github.com/stevenmaguire/oauth2-keycloak) for his `stevenmaguire/oauth2-keycloak` package upon which this wrapper is built. -->

<!-- ## Changelog -->
<!-- Please see [Changelog](CHANGELOG.md) for details. -->
