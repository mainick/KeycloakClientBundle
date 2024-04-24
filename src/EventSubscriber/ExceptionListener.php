<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\EventSubscriber;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final readonly class ExceptionListener
{
    public function __construct(
        private UrlGeneratorInterface $urlGenerator
    ) {
    }

    public function onKernelException(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();
        if ($exception instanceof IdentityProviderException) {
            $event->setResponse(new RedirectResponse($this->urlGenerator->generate('mainick_keycloak_security_auth_connect', [], UrlGeneratorInterface::ABSOLUTE_URL)));
        }
    }
}
