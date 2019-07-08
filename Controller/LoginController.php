<?php

/*
 * This file is part of the HWIOAuthBundle package.
 *
 * (c) Hardware.Info <opensource@hardware.info>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace HWI\Bundle\OAuthBundle\Controller;

use HWI\Bundle\OAuthBundle\Security\Core\Exception\AccountNotLinkedException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * @author Alexander <iam.asm89@gmail.com>
 */
final class LoginController extends AbstractController
{
    /**
     * @var bool
     */
    private $connect;

    /**
     * @var string
     */
    private $grantRule;

    /**
     * @var AuthenticationUtils
     */
    private $authenticationUtils;

    /**
     * @param bool                $connect
     * @param string              $grantRule
     * @param AuthenticationUtils $authenticationUtils
     */
    public function __construct(AuthenticationUtils $authenticationUtils, bool $connect, string $grantRule)
    {
        $this->authenticationUtils = $authenticationUtils;
        $this->connect = $connect;
        $this->grantRule = $grantRule;
    }

    /**
     * Action that handles the login 'form'. If connecting is enabled the
     * user will be redirected to the appropriate login urls or registration forms.
     *
     * @param Request $request
     *
     * @throws \LogicException
     *
     * @return Response
     */
    public function connectAction(Request $request)
    {
        $hasUser = $this->isGranted($this->grantRule);

        $error = $this->authenticationUtils->getLastAuthenticationError();

        // if connecting is enabled and there is no user, redirect to the registration form
        if ($this->connect && !$hasUser && $error instanceof AccountNotLinkedException) {
            $key = time();
            $session = $request->getSession();
            $session->set('_hwi_oauth.registration_error.'.$key, $error);

            return $this->redirectToRoute('hwi_oauth_connect_registration', ['key' => $key]);
        }

        if (null !== $error) {
            $error = $error->getMessageKey();
        }

        return $this->render('@HWIOAuth/Connect/login.html.twig', [
            'error' => $error,
        ]);
    }
}
