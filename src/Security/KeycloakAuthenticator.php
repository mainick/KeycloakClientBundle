<?php

namespace Mainick\KeycloakClientBundle\Security;

use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Interface\IamClientInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\InteractiveAuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\PreAuthenticatedUserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

final class KeycloakAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface, InteractiveAuthenticatorInterface
{
    private const STATE_KEY = 'state';
    private const STATE_SESSION_KEY = 'oauth2state';

    public function __construct(
        private LoggerInterface $keycloakClientLogger,
        private IamClientInterface $iamClient
    ) {
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        $request->getSession()->set(self::STATE_SESSION_KEY, $this->iamClient->getState());

        return new Response('', Response::HTTP_UNAUTHORIZED);
    }

    public function supports(Request $request): ?bool
    {
        return 'app_home' === $request->attributes->get('_route');
    }

    public function authenticate(Request $request): Passport
    {
        /*
        $sessionState = $request->getSession()->get(self::STATE_SESSION_KEY);
        $queryState = $request->query->get(self::STATE_KEY);
        if (null === $queryState || $queryState !== $sessionState) {
            throw new AuthenticationException(sprintf('query state (%s) is not the same as session state (%s)', $queryState ?? 'NULL', $sessionState ?? 'NULL'));
        }

        $request->getSession()->remove(self::STATE_SESSION_KEY);

        try {
            $token = $this->iamClient->authenticateByCode($request->query->get('code', ''));
        }
        catch (HttpExceptionInterface $e) {
            throw new AuthenticationException(sprintf('Bad status code returned by openID server (%s)', $e->getStatusCode()), previous: $e);
        }
        */
        /** @var AccessTokenInterface $token */
        $token = $request->getSession()->get('token');
        dd($token);

        if (!$token || !$token->getToken()) {
            $this->keycloakClientLogger->error('Authenticator::authenticate', [
                'error' => 'Token not found',
            ]);
            throw new AuthenticationException('Token not found');
        }

        if (!$token->getRefreshToken()) {
            $this->keycloakClientLogger->error('Authenticator::authenticate', [
                'error' => 'Refresh token not found',
            ]);
            throw new AuthenticationException('Refresh token not found');
        }

        $userBadge = new UserBadge($token->getToken(), fn () => $this->iamClient->userInfo($token));
        $passport = new SelfValidatingPassport($userBadge, [new PreAuthenticatedUserBadge()]);
        $passport->setAttribute(AccessTokenInterface::class, $token);

        return $passport;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse('/app/home');
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $request->getSession()->getBag('flashes')->add(
            'error',
            'An authentication error occured',
        );

        return new Response('', Response::HTTP_UNAUTHORIZED);
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $token = parent::createToken($passport, $firewallName);

        /** @var AccessTokenInterface $tokens */
        $tokens = $passport->getAttribute(AccessTokenInterface::class);
        if (null === $tokens) {
            throw new \LogicException(sprintf('Can\'t find %s in passport attributes', AccessTokenInterface::class));
        }
        $tokens->setExpires(time() + 3600);
        $token->setAttribute(AccessTokenInterface::class, $tokens);

        return $token;
    }

    public function isInteractive(): bool
    {
        return true;
    }
}
