<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\EventSubscriber;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

final readonly class TokenAuthListener implements EventSubscriberInterface
{
    public function __construct(
        private LoggerInterface $keycloakClientLogger,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => 'checkValidToken',
        ];
    }

    public function checkValidToken(RequestEvent $requestEvent): void
    {
        if (!$requestEvent->isMainRequest()) {
            return;
        }

        $request = $requestEvent->getRequest();
        $route = $request->attributes->get('_route');

        // Verifica se la rotta appartiene alla documentazione API generata da nelmio/api-doc-bundle
        if (in_array($route, ['app.swagger', 'app.swagger_ui'])) {
            return;
        }

        $jwtToken = $request->headers->get('X-Auth-Token');
        if (!$jwtToken) {
            $this->keycloakClientLogger->error('Token not found');
            $requestEvent->setResponse(new JsonResponse(['message' => 'Token not found'], Response::HTTP_UNAUTHORIZED));

            return;
        }

        $userInfo = $this->iam->userInfo($jwtToken);
        if (!$userInfo) {
            $this->keycloakClientLogger->error('Token not valid');
            $requestEvent->setResponse(new JsonResponse(['message' => 'Token not valid'], Response::HTTP_UNAUTHORIZED));

            return;
        }

        $request->attributes->set('user', $userInfo);
    }
}
