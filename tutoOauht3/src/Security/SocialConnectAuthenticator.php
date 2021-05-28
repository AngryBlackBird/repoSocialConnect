<?php


namespace App\Security;


use App\Controller\SecurityController;
use App\Repository\UserRepository;
use App\Security\Exception\NotVerifiedEmailException;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2Client;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Provider\GithubResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class SocialConnectAuthenticator extends SocialAuthenticator
{

    use TargetPathTrait;

    private $router;
    private $clientRegistry;
    private $userRepository;
    private $controller;


    private $service;


    public function __construct(RouterInterface $router, ClientRegistry $clientRegistry, UserRepository $userRepository, SecurityController $controller)
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->userRepository = $userRepository;
        $this->controller = $controller;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        return new RedirectResponse($this->router->generate('/login'));
    }

    public function supports(Request $request)
    {
        $this->service = $request->get('service');
        return 'oauth_check' === $request->attributes->get('_route') && ($request->get('service') === 'google' || 'github' || 'facebook');
    }

    public function getCredentials(Request $request)
    {
        return $this->fetchAccessToken($this->getClient());
    }

    /**
     * @param AccessToken $credentials
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        /** @var GenericResourceOwner $user */
        $user = $this->getClient()->fetchUserFromToken($credentials);

        if ($this->service == "github") {
            $response = HttpClient::create()->request(
                'GET',
                'https://api.github.com/user/emails',
                [
                    'headers' => [
                        'authorization' => "token {$credentials->getToken()}"
                    ]
                ]
            );
            $emails = json_decode($response->getContent(), true);
            foreach ($emails as $email) {
                if ($email['primary'] === true && $email['verified'] === true) {
                    $data = $user->toArray();
                    $data['email'] = $email['email'];
                    $user = new GithubResourceOwner($data);

                }
            }

            if ($user->getEmail() === NULL) {
                throw new NotVerifiedEmailException();
            }
        }
        if ($this->service == "google"|| $this->service == "facebook")  {
            if (!($user->toArray()["email_verified"] === true)) {
                throw new NotVerifiedEmailException();
            }
        }
        return $this->userRepository->findOrCreateFromOauth($user, $this->service);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($request->hasSession()) {
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }

        return new RedirectResponse($this->router->generate('app_login'));
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        $targetPath = $this->getTargetPath($request->getSession(), $providerKey);
        return new RedirectResponse($targetPath ?: '/');
    }


    public function getClient(): OAuth2Client
    {
        return $this->clientRegistry->getClient($this->service);
    }

}