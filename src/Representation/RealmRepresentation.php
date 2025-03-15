<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Representation;

use Mainick\KeycloakClientBundle\Annotation\Since;
use Mainick\KeycloakClientBundle\Representation\Collection\ClientCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\ClientScopeCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\GroupCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\ProtocolMapperCollection;
use Mainick\KeycloakClientBundle\Representation\Collection\UserCollection;
use Mainick\KeycloakClientBundle\Representation\Type\Map;

final class RealmRepresentation extends Representation
{
    public function __construct(
        public ?string $id = null,
        public ?string $realm = null,
        public ?string $displayName = null,
        public ?string $displayNameHtml = null,
        public ?int $notBefore = null,
        public ?string $defaultSignatureAlgorithm = null,
        public ?bool $revokeRefreshToken = null,
        public ?int $refreshTokenMaxReuse = null,
        public ?int $accessTokenLifespan = null,
        public ?int $accessTokenLifespanForImplicitFlow = null,
        public ?int $ssoSessionIdleTimeout = null,
        public ?int $ssoSessionMaxLifespan = null,
        public ?int $ssoSessionIdleTimeoutRememberMe = null,
        public ?int $ssoSessionMaxLifespanRememberMe = null,
        public ?int $offlineSessionIdleTimeout = null,
        public ?bool $offlineSessionMaxLifespanEnabled = null,
        public ?int $offlineSessionMaxLifespan = null,
        public ?int $clientSessionIdleTimeout = null,
        public ?int $clientSessionMaxLifespan = null,
        public ?int $clientOfflineSessionIdleTimeout = null,
        public ?int $clientOfflineSessionMaxLifespan = null,
        public ?int $accessCodeLifespan = null,
        public ?int $accessCodeLifespanUserAction = null,
        public ?int $accessCodeLifespanLogin = null,
        public ?int $actionTokenGeneratedByAdminLifespan = null,
        public ?int $actionTokenGeneratedByUserLifespan = null,
        public ?int $oauth2DeviceCodeLifespan = null,
        public ?int $oauth2DevicePollingInterval = null,
        public ?bool $enabled = null,
        public ?string $sslRequired = null,
        public ?bool $passwordCredentialGrantAllowed = null,
        public ?bool $registrationAllowed = null,
        public ?bool $registrationEmailAsUsername = null,
        public ?bool $rememberMe = null,
        public ?bool $verifyEmail = null,
        public ?bool $loginWithEmailAllowed = null,
        public ?bool $duplicateEmailsAllowed = null,
        public ?bool $resetPasswordAllowed = null,
        public ?bool $editUsernameAllowed = null,
        public ?bool $userCacheEnabled = null,
        public ?bool $realmCacheEnabled = null,
        public ?bool $bruteForceProtected = null,
        public ?bool $permanentLockout = null,
        #[Since('24.0.0')]
        public ?int $maxTemporaryLockouts = null,
        public ?int $maxFailureWaitSeconds = null,
        #[Since('24.0.0')]
        public ?int $minimumQuickLoginWaitSeconds = null,
        public ?int $waitIncrementSeconds = null,
        public ?int $quickLoginCheckMilliSeconds = null,
        public ?int $maxDeltaTimeSeconds = null,
        public ?int $failureFactor = null,
        public ?string $privateKey = null,
        public ?string $publicKey = null,
        public ?string $certificate = null,
        public ?string $codeSecret = null,
        public ?RolesRepresentation $roles = null,
        public ?GroupCollection $groups = null,
        /** @var string[]|null */
        public ?array $defaultRoles = null,
        public ?RoleRepresentation $defaultRole = null,
        public ?ClientRepresentation $adminPermissionsClient = null,
        /** @var string[]|null */
        public ?array $defaultGroups = null,
        /** @var string[]|null */
        public ?array $requiredCredentials = null,
        public ?string $passwordPolicy = null,
        public ?string $otpPolicyType = null,
        public ?string $otpPolicyAlgorithm = null,
        public ?int $otpPolicyInitialCounter = null,
        public ?int $otpPolicyDigits = null,
        public ?int $otpPolicyLookAheadWindow = null,
        public ?int $otpPolicyPeriod = null,
        #[Since('20.0.0')]
        public ?bool $otpPolicyCodeReusable = null,
        /** @var string[]|null */
        public ?array $otpSupportedApplications = null,
        public ?string $webAuthnPolicyRpEntityName = null,
        /** @var string[]|null */
        public ?array $webAuthnPolicySignatureAlgorithms = null,
        public ?string $webAuthnPolicyRpId = null,
        public ?string $webAuthnPolicyAttestationConveyancePreference = null,
        public ?string $webAuthnPolicyAuthenticatorAttachment = null,
        public ?string $webAuthnPolicyRequireResidentKey = null,
        public ?string $webAuthnPolicyUserVerificationRequirement = null,
        public ?int $webAuthnPolicyCreateTimeout = null,
        public ?bool $webAuthnPolicyAvoidSameAuthenticatorRegister = null,
        /** @var string[]|null */
        public ?array $webAuthnPolicyAcceptableAaguids = null,
        /** @var string[]|null */
        #[Since('23.0.0')]
        public ?array $webAuthnPolicyExtraOrigins = null,
        public ?string $webAuthnPolicyPasswordlessRpEntityName = null,
        /** @var string[]|null */
        public ?array $webAuthnPolicyPasswordlessSignatureAlgorithms = null,
        public ?string $webAuthnPolicyPasswordlessRpId = null,
        public ?string $webAuthnPolicyPasswordlessAttestationConveyancePreference = null,
        public ?string $webAuthnPolicyPasswordlessAuthenticatorAttachment = null,
        public ?string $webAuthnPolicyPasswordlessRequireResidentKey = null,
        public ?string $webAuthnPolicyPasswordlessUserVerificationRequirement = null,
        public ?int $webAuthnPolicyPasswordlessCreateTimeout = null,
        public ?bool $webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister = null,
        /** @var string[]|null */
        public ?array $webAuthnPolicyPasswordlessAcceptableAaguids = null,
        /** @var string[]|null */
        #[Since('23.0.0')]
        public ?array $webAuthnPolicyPasswordlessExtraOrigins = null,
        //public ?ClientProfiles $clientProfiles = null,
        //public ?ClientPolicies $clientPolicies = null,
        public ?UserCollection $users = null,
        public ?UserCollection $federatedUsers = null,
        //public ?ScopeMappingCollection $scopeMappings = null,
        public ?Map $clientScopeMappings = null,
        public ?ClientCollection $clients = null,
        public ?ClientScopeCollection $clientScopes = null,
        /** @var string[]|null */
        public ?array $defaultDefaultClientScopes = null,
        /** @var string[]|null */
        public ?array $defaultOptionalClientScopes = null,
        public ?Map $browserSecurityHeaders = null,
        public ?Map $smtpServer = null,
        //public ?UserFederationProviderCollection $userFederationProviders = null,
        //public ?UserFederationMapperCollection $userFederationMappers = null,
        public ?string $loginTheme = null,
        public ?string $accountTheme = null,
        public ?string $adminTheme = null,
        public ?string $emailTheme = null,
        public ?bool $eventsEnabled = null,
        public ?int $eventsExpiration = null,
        /** @var string[]|null */
        public ?array $eventsListeners = null,
        /** @var string[]|null */
        public ?array $enabledEventTypes = null,
        public ?bool $adminEventsEnabled = null,
        public ?bool $adminEventsDetailsEnabled = null,
        //public ?IdentityProviderCollection $identityProviders = null,
        //public ?IdentityProviderMapperCollection $identityProviderMappers = null,
        public ?ProtocolMapperCollection $protocolMappers = null,
        //public ?MultivaluedHashMap $components = null,
        public ?bool $internationalizationEnabled = null,
        /** @var string[]|null */
        public ?array $supportedLocales = null,
        public ?string $defaultLocale = null,
        //public ?AuthenticationFlowCollection $authenticationFlows = null,
        //public ?AuthenticatorConfigCollection $authenticatorConfig = null,
        //public ?RequiredActionProviderCollection $requiredActions = null,
        public ?string $browserFlow = null,
        public ?string $registrationFlow = null,
        public ?string $directGrantFlow = null,
        public ?string $resetCredentialsFlow = null,
        public ?string $clientAuthenticationFlow = null,
        public ?string $dockerAuthenticationFlow = null,
        #[Since('24.0.0')]
        public ?string $firstBrokerLoginFlow = null,
        public ?Map $attributes = null,
        public ?string $keycloakVersion = null,
        public ?bool $userManagedAccessAllowed = null,
//        #[Since('25.0.0')]
//        public ?bool $organizationsEnabled = null,
//        #[Since('25.0.0')]
//        public ?OrganizationCollection $organizations = null,
        #[Since('25.0.0')]
        public ?bool $verifiableCredentialsEnabled = null,
        #[Since('25.0.0')]
        public ?bool $adminPermissionsEnabled = null,
        #[Since('25.0.0')]
        public ?bool $social = null,
        #[Since('25.0.0')]
        public ?bool $updateProfileOnInitialSocialLogin = null,
        /** @var string[]|null */
        #[Since('25.0.0')]
        public ?array $socialProviders = null,
        /** @var string[]|null */
        #[Since('25.0.0')]
        public ?array $applicationScopeMappings = null,
//        #[Since('25.0.0')]
//        public ?ApplicationRepresentation $application = null,
//        #[Since('25.0.0')]
//        public ?OAuthClientRepresentation $oauthClients = null,
//        #[Since('25.0.0')]
//        public ?ClientTemplateRepresentation $clientTemplates = null,
        #[Since('25.0.0')]
        public ?int $oAuth2DeviceCodeLifespan = null,
        #[Since('25.0.0')]
        public ?int $oAuth2DevicePollingInterval = null,
    ) {
    }
}
