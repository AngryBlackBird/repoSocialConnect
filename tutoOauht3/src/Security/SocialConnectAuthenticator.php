<?php


namespace App\Security;


use App\Repository\UserRepository;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\OAuth2Client;
use KnpU\OAuth2ClientBundle\Client\Provider\GithubClient;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class SocialConnectAuthenticator extends SocialAuthenticator
{

    use TargetPathTrait;

    private $router;
    private $clientRegistry;
    private $userRepository;
    private $service;

    public function __construct(RouterInterface $router, ClientRegistry $clientRegistry, UserRepository $userRepository)
    {
        $this->router = $router;
        $this->clientRegistry = $clientRegistry;
        $this->userRepository = $userRepository;
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
        ///** @var GenericResourceOwner $user */
        //$user = $this->getClient()->fetchUserFromToken($credentials);
        dd($credentials);
       // return $this->userRepository->findOrCreateFromGithubOauth($user);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        // TODO: Implement onAuthenticationFailure() method.
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        // TODO: Implement onAuthenticationSuccess() method.
    }


    public function getClient(): OAuth2Client
    {
        return $this->clientRegistry->getClient($this->service);
    }

}