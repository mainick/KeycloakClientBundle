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
    # Optional: Whitelist of allowed domains for JWKS endpoint (security feature)
    # If not specified, only the domain from base_url is allowed
    allowed_jwks_domains:
      - 'keycloak.example.com'
      - '*.auth.example.com'  # Supports wildcard subdomains
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
IAM_ENCRYPTION_ALGORITHM='<your-algorithm>' # RS256, HS256, JWKS, etc.
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

By configuring the package before installation, you ensure that it will be ready to use once installed.

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
// authenticate the user with username and password
$accessToken = $this->iamClient->authenticate($username, $password);

// authenticate the user with authorization code
$accessToken = $this->iamClient->authenticateCodeGrant($authorizationCode);

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

#### Retrieve user information

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
use Mainick\KeycloakClientBundle\Annotation\ExcludeTokenValidationAttribute;
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

## Symfony Security Configuration

### Bundle configuration

To use the `KeycloakClientBundle` with Symfony's security component, you need to configure the security system to use the Keycloak client.

First you need to add a new section to the bundle configuration file:

```yaml
# config/packages/mainick_keycloak_client.yaml
mainick_keycloak_client:
  security:
    default_target_route_name: '%env(TARGET_ROUTE_NAME)%'
```

Then you need to configure the Keycloak redirect uri to the `mainick_keycloak_security_auth_connect_check` bundle route, which redirects to the default route or referer route after successful login.

It's recommended to change the following environment variable to your project's environment file
(e.g., `.env` or `.env.local`) with the uri. The same URI must be configured in the Keycloak application client:

```shell
###> mainick/keycloak-client-bundle ###
IAM_REDIRECT_URI='https://app.local/auth/keycloak/check'
TARGET_ROUTE_NAME=app_home
###< mainick/keycloak-client-bundle ###
```

Below is the complete configuration file:

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
  security:
      default_target_route_name: '%env(TARGET_ROUTE_NAME)%'
```

### Route configuration

Create a new file in ```config/routes/``` to load pre configured bundle routes.

```yaml
# config/routes/mainick_keycloak_security.yaml
mainick_keycloak_security_auth_connect:
  path:       /auth/keycloak/connect
  controller: Mainick\KeycloakClientBundle\Controller\KeycloakController::connect

mainick_keycloak_security_auth_connect_check:
  path:       /auth/keycloak/check
  controller: Mainick\KeycloakClientBundle\Controller\KeycloakController::connectCheck

mainick_keycloak_security_auth_logout:
  path:       /auth/keycloak/logout
  controller: Mainick\KeycloakClientBundle\Controller\KeycloakController::logout
```

### Security configuration

Then you need to configure the security system to use the Keycloak client.
You can do this by adding the following configuration to your `config/packages/security.yaml` file to use the bundle's UserProvider:

```yaml
# config/packages/security.yaml
providers:
  mainick_keycloak_user_provider:
    id: Mainick\KeycloakClientBundle\Security\User\KeycloakUserProvider
```

Here is a simple configuration that restrict access to ```/app/*``` routes only to user with roles "ROLE_USER" or "ROLE_ADMIN" :

```yaml
# config/packages/security.yaml
security:
  providers:
    mainick_keycloak_user_provider:
      id: Mainick\KeycloakClientBundle\Security\User\KeycloakUserProvider

  firewalls:
    dev:
      pattern: ^/(_(profiler|wdt)|css|images|js)/
      security: false

    auth_connect:
      pattern: /auth/keycloak/connect
      security: false

    secured_area:
      pattern: ^/
      provider: mainick_keycloak_user_provider
      entry_point: Mainick\KeycloakClientBundle\Security\EntryPoint\KeycloakAuthenticationEntryPoint
      custom_authenticator:
        - Mainick\KeycloakClientBundle\Security\Authenticator\KeycloakAuthenticator
      logout:
        path: mainick_keycloak_security_auth_logout

  role_hierarchy:
    ROLE_ADMIN: ROLE_USER

  # Easy way to control access for large sections of your site
  # Note: Only the *first* access control that matches will be used
  access_control:
    - { path: ^/app, roles: ROLE_ADMIN }
```

### Logout

To logout the user, you can use the following code:

```php
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Annotation\Route;
use Mainick\KeycloakClientBundle\Annotation\ExcludeTokenValidationAttribute;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class MyController extends AbstractController
{
    #[Route("/logout", name: "app.logout", methods: ["GET"])]
    public function logout(): RedirectResponse
    {
        return $this->redirectToRoute('mainick_keycloak_security_auth_logout');
    }
}
```

or create a link in your twig template:

```twig
<a href="{{ path('mainick_keycloak_security_auth_logout') }}">Logout</a>
```

This will redirect the user to the Keycloak logout page, where the user will be logged out from the Keycloak server.

### Redirect after login

To redirect the user to a specific route after login, you can set the `TARGET_ROUTE_NAME` environment variable
to the desired route name.

```shell
###> mainick/keycloak-client-bundle ###
TARGET_ROUTE_NAME=app_home
###< mainick/keycloak-client-bundle ###
```

This will redirect the user to the `app_home` route after a successful login.

### Troubleshooting - You have Access Denied in your browser

If you have an Access Denied error in your browser, it is maybe because scope roles is misconfigured.

For correction:

1. Check whether the **ROLE_ADMIN** and **ROLE_USER** roles have been created for the application client.
2. Click on **Client scopes** on left panel, then **roles**:
3. Click on **Mappers** tab, then **client roles**:
4. Disabled **Add to userinfo**, click on **Save**, then enabled **Add to userinfo** and click on **Save**:

Please check the roles assigned to the user in Keycloak and the roles configured in the Symfony security configuration.


## KeycloakAdminClient Provider

The `KeycloakAdminClient` provider allows you to interact with the Keycloak Admin REST API. It provides a convenient way to manage Keycloak resources such as realms, clients, users, groups, and roles.

### Configuration

To use the `KeycloakAdminClient` provider, you need to configure it in your services.yaml file:

```yaml
services:
    Mainick\KeycloakClientBundle\Interface\IamAdminClientInterface:
        alias: Mainick\KeycloakClientBundle\Provider\KeycloakAdminClient
```

You also need to add the following environment variables to your project's environment file:

```shell
###> mainick/keycloak-client-bundle ###
IAM_ADMIN_REALM='master' # Keycloak admin realm name
IAM_ADMIN_CLIENT_ID='admin-cli' # Keycloak admin client id
IAM_ADMIN_USERNAME='admin' # Keycloak admin username
IAM_ADMIN_PASSWORD='admin' # Keycloak admin password
###< mainick/keycloak-client-bundle ###
```

### Usage

You can use the `KeycloakAdminClient` provider by injecting the `Mainick\KeycloakClientBundle\Interface\IamAdminClientInterface` interface in your controller or service:

```php
<?php

declare(strict_types=1);

namespace App\Service;

use Mainick\KeycloakClientBundle\Interface\IamAdminClientInterface;

class IamAdminService
{
    public function __construct(
        private IamAdminClientInterface $iamAdminClient
    ) {
    }
}
```

### Examples

#### Representations

You can retrieve the list of representations for each Keycloak entity:

```php
// List all realms: RealmCollection of the RealmRepresentation
$realms = $iamAdminClient->realms()->all();

// List all clients: ClientCollection of the ClientRepresentation
$clients = $iamAdminClient->clients()->all(realm: 'realm-test');

// List all users: UserCollection of the UserRepresentation
$users = $iamAdminClient->users()->all(realm: 'realm-test');

// List all groups: GroupCollection of the GroupRepresentation
$groups = $iamAdminClient->groups()->all(realm: 'realm-test');

// List all roles: RoleCollection of the RoleRepresentation
$roles = $iamAdminClient->roles()->all(realm: 'realm-test');
```

You can retrieve a single representation by its ID:

```php
// Get a realm by name
$realmRepresentation = $iamAdminClient->realms()->get(realm: 'realm-test');

// Get a client by UUID
$clientRepresentation = $iamAdminClient->clients()->get(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd'
);

// Get a user by ID
$userRepresentation = $iamAdminClient->users()->get(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);

// Get a group by ID
$groupRepresentation = $iamAdminClient->groups()->get(
    realm: 'realm-test',
    groupId: '190990fa-cdbf-4b31-b561-0cfc03737414'
);

// Get a realm role by name
$roleRealmRepresentation = $iamAdminClient->roles()->get(
    realm: 'realm-test',
    roleName: 'ROLE_USER_VIEW'
);

// Get a client role by name
$roleClientRepresentation = $iamAdminClient->clients()->role(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    roleName: 'ROLE_ADD_AGENT'
);
```

You can create a new representation:

```php
// Create a new realm
$realmRepresentation = new RealmRepresentation(
    realm: 'realm-test',
    displayName: 'Test Realm',
    enabled: true,
);
$realmCreated = $iamAdminClient->realms()->create($realmRepresentation);

// Create a new client (specify the realm)
$clientRepresentation = new ClientRepresentation(
    name: 'client-test',
    enabled: true,
);
$clientCreated = $iamAdminClient->clients()->create(
    realm: 'realm-test',
    client: $clientRepresentation
);
```

You can update a representation:

```php
// Update a realm
$realmRepresentation = $iamAdminClient->realms()->get(realm: 'realm-test');
$realmRepresentation->displayName = 'New display name';
$realmUpdated = $iamAdminClient->realms()->update($realm, $realmRepresentation);

// Update a client (specify the realm)
$clientRepresentation = $iamAdminClient->clients()->get(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd'
);
$clientRepresentation->description = 'Client test updated';
$clientUpdated = $iamAdminClient->clients()->update(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    clientRepresentation: $clientRepresentation
);
```

You can delete a representation:

```php
// Delete a realm
$realmDeleted = $iamAdminClient->realms()->delete(realm: 'realm-test');

// Delete a client (specify the realm)
$clientDeleted = $iamAdminClient->clients()->delete(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd'
);
```

#### User Operations

You can retrieve user sessions:

```php
// List all sessions: UserSessionCollection of the UserSessionRepresentation
$sessions = $iamAdminClient->users()->sessions(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);
```

You can retrieve user groups:

```php
// List all groups: GroupCollection of the GroupRepresentation
$groups = $iamAdminClient->users()->groups(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);
```

You can add a user to a group:

```php
$groups = $iamAdminClient->users()->joinGroup(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3',
    groupId: '190990fa-cdbf-4b31-b561-0cfc03737414'
);
```

You can remove a user from a group:

```php
$groups = $iamAdminClient->users()->leaveGroup(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3',
    groupId: '190990fa-cdbf-4b31-b561-0cfc03737414'
);
```

You can retrieve user roles:

```php
// List all realm roles: RoleCollection of the RoleRepresentation
$userRolesRealm = $iamAdminClient->users()->realmRoles(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);

// List all client roles: RoleCollection of the RoleRepresentation
$userRolesClient = $iamAdminClient->users()->clientRoles(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);
```

You can retrieve available user roles:

```php
// List all available realm roles: RoleCollection of the RoleRepresentation
$userRolesRealm = $iamAdminClient->users()->availableRealmRoles(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);

// List all available client roles: RoleCollection of the RoleRepresentation
$userRolesClient = $iamAdminClient->users()->availableClientRoles(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);
```

You can assign a role to a user:

```php
// Assign a realm role to a user
$roleRealmRepresentation = $iamAdminClient->roles()->get(
    realm: 'realm-test',
    roleName: 'ROLE_REALM_TEST',
);
$iamAdminClient->users()->addRealmRole(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3',
    role: $roleRealmRepresentation
);

// Assign a client role to a user
$roleClientRepresentation = $iamAdminClient->clients()->role(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    roleName: 'ROLE_CLIENT_TEST',
);
$iamAdminClient->users()->addClientRole(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3',
    role: $roleClientRepresentation
);
```

You can remove a role from a user:

```php
// Remove a realm role from a user
$roleRealmRepresentation = $iamAdminClient->roles()->get(
    realm: 'realm-test',
    roleName: 'ROLE_REALM_TEST',
);
$iamAdminClient->users()->removeRealmRole(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3',
    role: $roleRealmRepresentation
);

// Remove a client role from a user
$roleClientRepresentation = $iamAdminClient->clients()->role(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    roleName: 'ROLE_CLIENT_TEST',
);
$iamAdminClient->users()->removeClientRole(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3',
    role: $roleClientRepresentation
);
```

#### Group Operations

You can retrieve subgroups:

```php
/** @var GroupCollection $groups */
$groups = $iamAdminClient->groups()->all(realm: 'realm-test');
if ($groups->count()) {
    $level = 1;
    foreach ($groups as $group) {
        echo sprintf('%s> Group "%s"'."<br/>", str_repeat('-', $level), $group->name);

        if ($group->subGroupCount) {
            /** @var GroupCollection $subGroups */
            $subGroups = $iamAdminClient->groups()->children(
                realm: 'realm-test',
                groupId: $group->id
            );
            if ($subGroups->count()) {
                $level++;
                foreach ($subGroups as $subGroup) {
                    echo sprintf('%s> SubGroup "%s"'."<br/>", str_repeat('-', $level), $subGroup->name);
                }
            }
        }
    }
}
```

You can create a subgroup:

```php
$subGroupRepresentation = new GroupRepresentation(
    name: 'Test Sub Group',
);
$groups = $iamAdminClient->groups()->createChild(
    realm: 'realm-test',
    parentGroupId: '190990fa-cdbf-4b31-b561-0cfc03737414',
    group: $subGroupRepresentation
);
```

You can retrieve users in a group:

```php
// List all users: UserCollection of the UserRepresentation
$users = $iamAdminClient->groups()->users(
    realm: 'realm-test',
    groupId: '190990fa-cdbf-4b31-b561-0cfc03737414'
);
```

#### Role Operations

You can retrieve roles:

```php
// List all realm roles: RoleCollection of the RoleRepresentation
$rolesRealm = $iamAdminClient->roles()->all(realm: 'realm-test');

// List all client roles: RoleCollection of the RoleRepresentation
$rolesClient = $iamAdminClient->clients()->roles(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd'
);
```

You can create a new role:

```php
// Create a new realm role
$roleRepresentation = new RoleRepresentation(
    name: 'ROLE_REALM_TEST',
    description: 'Role Realm for test',
);
$roleRealm = $iamAdminClient->roles()->create(
    realm: 'realm-test',
    role: $roleRepresentation
);

// Create a new client role
$roleRepresentation = new RoleRepresentation(
    name: 'ROLE_CLIENT_TEST',
    description: 'Role Client for test',
);
$roleClient = $iamAdminClient->clients()->createRole(
    realm: $realm,
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    role: $roleRepresentation
);
```

You can update a role:

```php
// Update a realm role
$roleRealmRepresentation = $iamAdminClient->roles()->get(
    realm: 'realm-test',
    roleName: 'ROLE_REALM_TEST',
);
$roleRealmRepresentation->description = 'Description test';
$roleRealmUpdated = $iamAdminClient->roles()->update(
    realm: 'realm-test',
    roleName: 'ROLE_REALM_TEST',
    roleRepresentation: $roleRealmRepresentation,
);

// Update a client role
$roleClientRepresentation = $iamAdminClient->clients()->role(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    roleName: 'ROLE_CLIENT_TEST',
);
$roleClientRepresentation->description = 'Description test';
$roleClientUpdated = $iamAdminClient->clients()->updateRole(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    roleName: 'ROLE_CLIENT_TEST',
    roleRepresentation: $roleClientRepresentation,
);
```

You can delete a role:

```php
// Delete a realm role
$roleRealmDeleted = $iamAdminClient->roles()->delete(
    realm: 'realm-test',
    roleName: 'ROLE_REALM_TEST',
);

// Delete a client role
$roleClientDeleted = $iamAdminClient->clients()->deleteRole(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd',
    roleName: 'ROLE_CLIENT_TEST'
);
```

#### User Profile Configuration

You can retrieve the user profile configuration:

```php
$userProfileConfig = $iamAdminClient->users()->getProfileConfig($realm);
```

You can check if unmanaged attributes are enabled:

```php
if ($userProfileConfig->unmanagedAttributePolicy === UnmanagedAttributePolicyEnum::ADMIN_EDIT) {
    echo "Unmanaged attribute policy is set to ADMIN_EDIT. You can edit unmanaged attributes.";
}
```

You can add an unmanaged attribute:

```php
$user = $iamAdminClient->users()->get(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);
$user->attributes = $user->attributes->with('school', ['school1', 'school2']);

$userUpdated = $iamAdminClient->users()->update(
    realm: 'realm-test',
    userId: $user->id,
    user: $user);
```

You can update an unmanaged attribute:

```php
$user = $iamAdminClient->users()->get(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);
$user->attributes = $user->attributes->with('social', ['mainick-facebook']);

$userUpdated = $iamAdminClient->users()->update(
    realm: 'realm-test',
    userId: $user->id,
    user: $user
);
```

You can remove an unmanaged attribute:

```php
$user = $iamAdminClient->users()->get(
    realm: 'realm-test',
    userId: '8cd92f79-7919-4486-a0fb-0cb7dd517ac3'
);
$user->attributes = $user->attributes->without('social');

$userUpdated = $iamAdminClient->users()->update(
    realm: 'realm-test',
    userId: $user->id,
    user: $user
);
```

#### User Sessions

You can retrieve user sessions for a specific client:

```php
$userSessions = $iamAdminClient->clients()->getUserSessions(
    realm: 'realm-test',
    clientUuid: '32f77927-0bfd-4ef2-8e27-2932984634cd'
);
if ($userSessions->count()) {
    echo sprintf('Client %s has %d user sessions %s', $client->clientId, $userSessions->count(), PHP_EOL);
}
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

Please see [CONTRIBUTING](https://github.com/mainick/KeycloakClientBundle/blob/main/CONTRIBUTING.md) for details.

<!-- ## Contributing -->
<!-- Please see [Contributing](CONTRIBUTING.md) for details. -->

<!-- ## Acknowledgments -->
<!-- A big thank you to [Steven Maguire](https://github.com/stevenmaguire/oauth2-keycloak) for his `stevenmaguire/oauth2-keycloak` package upon which this wrapper is built. -->

<!-- ## Changelog -->
<!-- Please see [Changelog](CHANGELOG.md) for details. -->
