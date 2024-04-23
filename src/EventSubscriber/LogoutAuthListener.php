<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\EventSubscriber;

use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Mainick\KeycloakClientBundle\Token\KeycloakResourceOwner;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

final readonly class LogoutAuthListener
{
    public function __construct(
        private LoggerInterface $keycloakClientLogger,
        private UrlGeneratorInterface $urlGenerator,
        private TokenStorageInterface $tokenStorage,
        private IamClientInterface $iamClient,
        private string $defaultTargetRouteName
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $this->keycloakClientLogger->info('LogoutAuthListener::__invoke');
        if (null === $event->getToken() || null === $event->getToken()->getUser()) {
            return;
        }

        $user = $event->getToken()->getUser();
        if (!$user instanceof KeycloakResourceOwner) {
            return;
        }

        $logoutUrl = $this->iamClient->logoutUrl([
            'state' => $user->getAccessToken()->getValues()['session_state'],
            'access_token' => $user->getAccessToken(),
            'redirect_uri' => $this->urlGenerator->generate($this->defaultTargetRouteName, [], UrlGeneratorInterface::ABSOLUTE_URL),
        ]);
        $this->keycloakClientLogger->info('LogoutAuthListener::__invoke', [
            'logoutUrl' => $logoutUrl,
            'token' => $this->tokenStorage->getToken(),
        ]);

        $this->tokenStorage->setToken(null);
        $event->getRequest()->getSession()->invalidate();

        $event->setResponse(new RedirectResponse($logoutUrl));
    }
}
