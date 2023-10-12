KeycloakClientBundle
====================

[![Latest Version](https://img.shields.io/github/release/mainick/KeycloakClientBundle.svg?style=flat-square)](https://github.com/mainick/KeycloakClientBundle/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Total Downloads](https://img.shields.io/packagist/dt/mainick/keycloak-client-bundle.svg?style=flat-square)](https://packagist.org/packages/mainick/keycloak-client-bundle)

The `KeycloakClientBundle` bundle is a wrapper for the `stevenmaguire/oauth2-keycloak` package,
designed to simplify Keycloak integration into your application in Symfony and provide additional functionality
for token management and user information access.
It also includes a listener to verify the token on every request.

## Configuration

Before installing this package, you need to configure it manually.
You can do this by creating a `mainick_keycloak_client.yaml` file in the `config/packages` directory of your project
and adding the following configuration:

```yaml
# config/packages/mainick_keycloak_client.yaml

mainick_keycloak_client:
  keycloak:
    verify_ssl: '%env(bool:IAM_VERIFY_SSL)%'
    base_url: '%env(IAM_BASE_URL)%'
    realm: '%env(IAM_REALM)%'
    client_id: '%env(IAM_CLIENT_ID)%'
    client_secret: '%env(IAM_CLIENT_SECRET)%'
    redirect_uri: '%env(IAM_REDIRECT_URI)%'
    encryption_algorithm: '%env(IAM_ENCRYPTION_ALGORITHM)%'
    encryption_key: '%env(IAM_ENCRYPTION_KEY)%'
    encryption_key_path: '%env(IAM_ENCRYPTION_KEY_PATH)%'
    version: '%env(IAM_VERSION)%'
```

Additionally, it's recommended to add the following environment variables to your project's environment file
(e.g., `.env` or `.env.local`) with the appropriate values for your configuration:

```shell
###> mainick/keycloak-client-bundle ###
IAM_VERIFY_SSL=true # Verify SSL certificate
IAM_BASE_URL='<your-base-server-url>'  # Keycloak server URL
IAM_REALM='<your-realm>' # Keycloak realm name
IAM_CLIENT_ID='<your-client-id>' # Keycloak client id
IAM_CLIENT_SECRET='<your-client-secret>' # Keycloak client secret
IAM_REDIRECT_URI='<your-redirect-uri>' # Keycloak redirect uri
IAM_ENCRYPTION_ALGORITHM='<your-algorithm>' # RS256, HS256, etc.
IAM_ENCRYPTION_KEY='<your-public-key>' # public key
IAM_ENCRYPTION_KEY_PATH='<your-public-key-path>' # public key path
IAM_VERSION='<your-version-keycloak>' # Keycloak version
###< mainick/keycloak-client-bundle ###
```

Make sure to replace the placeholder values with your actual configuration values.
Once you have configured the package and environment variables, you can proceed with the installation.

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

Configurando il pacchetto prima dell'installazione, ti assicuri che sarà pronto per l'uso una volta installato.

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

The KeycloakClientBundle includes a built-in listener, `TokenAuthListener`, that automatically validates the
JWT token on every request, ensuring the security and validity of your Keycloak integration.
This listener seamlessly handles token validation, allowing you to focus on your application's logic.

#### Using TokenAuthListener

In your Symfony project, add the `TokenAuthListener` to your `config/services.yaml` file as a registered service
and tag it as a `kernel.event_listener`. This will enable the listener to trigger on every request.

```yaml
services:
    Mainick\KeycloakClientBundle\EventSubscriber\TokenAuthListener:
        tags:
          - { name: kernel.event_listener, event: kernel.request, method: checkValidToken, priority: 0 }
```

Additionally, the `TokenAuthListener` adds an `user` attribute to the Symfony request object,
which contains the `UserRepresentationDTO` object.

```php
// get the user object from the request
$user = $request->attributes->get('user');
```

This `user` attribute contains the user information fetched from the JWT token and is an instance
of the `UserRepresentationDTO` class.
This allows your application to easily access user-related data when processing requests.

#### Excluding Routes from Token Validation

`TokenAuthListener` verifies the token for all incoming requests by default. However,
if you have specific routes for which you want to exclude token validation,
you can do so using the `ExcludeTokenValidationAttribute` attribute.

To exclude token validation for a particular route, apply the `ExcludeTokenValidationAttribute` to the
corresponding controller method.

```php
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use App\Attribute\ExcludeTokenValidationAttribute;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class MyController extends AbstractController
{
    #[Route("/path/to/excluded/route", name: "app.excluded_route", methods: ["GET"])]
    #[ExcludeTokenValidationAttribute]
    public function excludedRouteAction(): Response
    {
        // This route is excluded from token validation.
        // ...
    }
}
```

When the `ExcludeTokenValidationAttribute` is applied to a method, `TokenAuthListener` will skip token validation
for requests to that specific route.

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

Please see [CONTRIBUTING](https://github.com/mainick/KeycloakClientBundle/blob/main/CONTRIBUTING.md) for details.

<!-- ## Contributing -->
<!-- Please see [Contributing](CONTRIBUTING.md) for details. -->

<!-- ## Acknowledgments -->
<!-- A big thank you to [Steven Maguire](https://github.com/stevenmaguire/oauth2-keycloak) for his `stevenmaguire/oauth2-keycloak` package upon which this wrapper is built. -->

<!-- ## Changelog -->
<!-- Please see [Changelog](CHANGELOG.md) for details. -->
