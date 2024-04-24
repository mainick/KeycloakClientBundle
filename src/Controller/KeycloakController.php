<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Controller;

use Mainick\KeycloakClientBundle\DTO\KeycloakAuthorizationCodeEnum;
use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class KeycloakController extends AbstractController
{
    public function __construct(
        private readonly LoggerInterface $keycloakClientLogger,
        private readonly IamClientInterface $iamClient
    ) {
    }

    #[Route('/auth/keycloak/connect', name: 'mainick_keycloak_security_auth_connect', methods: ['GET'])]
    public function connect(Request $request): Response
    {
        $authorizationUrl = $this->iamClient->getAuthorizationUrl();
        $this->keycloakClientLogger->info('KeycloakController::connect', [
            'authorizationUrl' => $authorizationUrl,
        ]);
        if ($request->hasSession()) {
            $request->getSession()->set(KeycloakAuthorizationCodeEnum::STATE_SESSION_KEY, $this->iamClient->getState());
        }

        return $this->redirect($authorizationUrl);
    }

    #[Route('/auth/keycloak/check', name: 'mainick_keycloak_security_auth_connect_check', methods: ['GET'])]
    public function connectCheck(Request $request, string $defaultTargetRouteName): Response
    {
        $loginReferrer = null;
        if ($request->hasSession()) {
            $loginReferrer = $request->getSession()->remove(KeycloakAuthorizationCodeEnum::LOGIN_REFERRER);
        }
        $this->keycloakClientLogger->info('KeycloakController::connectCheck', [
            'defaultTargetRouteName' => $defaultTargetRouteName,
            'loginReferrer' => $loginReferrer,
        ]);

        return $loginReferrer ? $this->redirect($loginReferrer) : $this->redirect($defaultTargetRouteName);
    }

    #[Route('/auth/keycloak/logout', name: 'mainick_keycloak_security_auth_logout', methods: ['GET'])]
    public function logout(string $defaultTargetRouteName): Response
    {
        $this->keycloakClientLogger->info('KeycloakController::logout', [
            'defaultTargetRouteName' => $defaultTargetRouteName,
        ]);

        return $this->redirect($defaultTargetRouteName);
    }
}
