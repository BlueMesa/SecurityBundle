<?php

/*
 * Copyright 2013 Radoslaw Kamil Ejsmont <radoslaw@ejsmont.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Bluemesa\Bundle\SecurityBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Security;

/**
 * This controller handles security
 *
 * @author Radoslaw Kamil Ejsmont <radoslaw@ejsmont.net>
 */
class SecurityController extends Controller
{
    /**
     * @param  Request $request
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function loginAction(Request $request)
    {
        $error = $this->getAuthenticationError($request);

        return $this->render('BluemesaImapAuthenticationBundle:Default:login.html.twig', array(
            'last_username' => $request->getSession()->get(Security::LAST_USERNAME),
            'error'         => $error,
            'token'         => $this->generateToken(),
        ));
    }

    /**
     * @param  Request $request
     * @return string
     */
    protected function getAuthenticationError($request)
    {
        if ($request->attributes->has(Security::AUTHENTICATION_ERROR)) {
            return $request->attributes->get(Security::AUTHENTICATION_ERROR);
        }

        return $request->getSession()->get(Security::AUTHENTICATION_ERROR);
    }

    /**
     * @return string
     */
    protected function generateToken()
    {
        $token = $this->get('security.csrf.token_manager')->getToken('authenticate');

        return $token;
    }
}
