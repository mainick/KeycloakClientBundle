<?php

declare(strict_types=1);

namespace Mainick\KeycloakClientBundle\Service;

use GuzzleHttp\ClientInterface as HttpClientInterface;
use GuzzleHttp\Exception\ClientException;
use Mainick\KeycloakClientBundle\Interface\AccessTokenInterface;
use Mainick\KeycloakClientBundle\Provider\KeycloakAdminClient;
use Mainick\KeycloakClientBundle\Representation\Collection\Collection;
use Mainick\KeycloakClientBundle\Representation\Representation;
use Mainick\KeycloakClientBundle\Token\AccessToken;
use PhpParser\JsonDecoder;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;

abstract class Service
{
    private ?AccessTokenInterface $adminAccessToken;
    private HttpClientInterface $httpClient;

    public function __construct(
        protected readonly LoggerInterface $logger,
        protected readonly KeycloakAdminClient $keycloakAdminClient,
    ) {
        $this->adminAccessToken = null;
        $this->httpClient = $this->keycloakAdminClient->getKeycloakProvider()->getHttpClient();
    }

    protected function executeQuery(string $path, ?Criteria $criteria = null): mixed
    {
        if (!$this->isAuthorized()) {
            $this->inizializeAdminAccessToken();
        }

        $response = $this->httpClient->request(
            HttpMethodEnum::GET->value,
            $path . $this->getQueryParams($criteria),
            $this->defaultOptions()
        );

        if ($this->isSuccessful($response->getStatusCode())) {
            $this->logger->info('KeycloakAdminClient::Realms::all', [
                'status_code' => $response->getStatusCode(),
                'response' => $response->getBody()->getContents(),
            ]);

            return (new JsonDecoder())->decode($response->getBody()->getContents());
        }

        return null;
    }

    protected function executeCommand(
        HttpMethodEnum $method,
        string $path,
        Representation|Collection|array|null $payload = null
    ): bool
    {
        if (!$this->isAuthorized()) {
            $this->inizializeAdminAccessToken();
        }

        $options = $this->defaultOptions();
        if (null !== $payload) {
            $options['json'] = $payload instanceof \JsonSerializable ? $payload->jsonSerialize() : $payload;
        }

        $response = $this->httpClient->request(
            $method->value,
            $path,
            $options
        );

        if ($this->isSuccessful($response->getStatusCode())) {
            $this->logger->info('KeycloakAdminClient::Realms::create', [
                'status_code' => $response->getStatusCode(),
                'response' => $response->getBody()->getContents(),
            ]);

            return true;
        }

        return false;
    }

    private function defaultOptions(): array
    {
        return [
            'base_uri' => $this->keycloakAdminClient->getBaseUrl(),
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer '.$this->adminAccessToken->getToken(),
            ],
        ];
    }

    private function getQueryParams(?Criteria $criteria): string
    {
        if (null === $criteria) {
            return '';
        }

        return '?' . http_build_query($criteria->jsonSerialize());
    }

    private function isSuccessful($statusCode): bool
    {
        return ($statusCode >= Response::HTTP_OK && $statusCode < Response::HTTP_MULTIPLE_CHOICES) || $statusCode === Response::HTTP_NOT_MODIFIED;
    }

    private function isAuthorized(): bool
    {
        return null !== $this->adminAccessToken && false === $this->adminAccessToken->hasExpired();
    }

    private function inizializeAdminAccessToken(): void
    {
        try {
            if (null === $this->adminAccessToken) {
                throw new \Exception('No refresh token available');
            }

            $token = $this->keycloakAdminClient->getKeycloakProvider()->getAccessToken('refresh_token', [
                'refresh_token' => $this->adminAccessToken->getRefreshToken(),
            ]);
        }
        catch (\Exception $e) {
            try {
                $token = $this->keycloakAdminClient->getKeycloakProvider()->getAccessToken('password', [
                    'username' => $this->keycloakAdminClient->getUsername(),
                    'password' => $this->keycloakAdminClient->getPassword(),
                ]);
            }
            catch (\Exception $e) {
                $this->logger->error('KeycloakAdminClient::getAdminAccessToken', [
                    'error' => $e->getMessage(),
                ]);

                return;
            }
        }

        $accessToken = new AccessToken();
        $accessToken
            ->setToken($token->getToken())
            ->setExpires($token->getExpires())
            ->setRefreshToken($token->getRefreshToken())
            ->setValues($token->getValues());

        $this->logger->info('KeycloakAdminClient::getAdminAccessToken', [
            'token' => $accessToken->getToken(),
            'expires' => $accessToken->getExpires(),
            'refresh_token' => $accessToken->getRefreshToken(),
        ]);

        $this->adminAccessToken = $accessToken;
    }
}
