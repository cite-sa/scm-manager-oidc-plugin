/*
 * MIT License
 *
 * Copyright (c) 2020-present Cloudogu GmbH and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package gr.cite.scm.plugin.oidc.browser;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import sonia.scm.security.AccessToken;
import sonia.scm.security.AccessTokenBuilder;
import sonia.scm.security.AccessTokenBuilderFactory;
import sonia.scm.security.AccessTokenCookieIssuer;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OidcLoginHandler {

    private final AccessTokenBuilderFactory tokenBuilderFactory;
    private final AccessTokenCookieIssuer cookieIssuer;

    @Inject
    public OidcLoginHandler(AccessTokenBuilderFactory tokenBuilderFactory, AccessTokenCookieIssuer cookieIssuer) {
        this.tokenBuilderFactory = tokenBuilderFactory;
        this.cookieIssuer = cookieIssuer;
    }

    /**
     * Generates an authentication token for the current session and saves it.
     *
     * @param request
     * @param response
     * @param token
     * @throws AuthenticationException
     */
    public void login(HttpServletRequest request, HttpServletResponse response, OidcAuthenticationToken token) throws AuthenticationException {
        Subject subject = SecurityUtils.getSubject();
        subject.login(token);

        PrincipalCollection principalCollection = subject.getPrincipals();

        AccessTokenBuilder accessTokenBuilder = tokenBuilderFactory.create();
        accessTokenBuilder.subject(principalCollection.getPrimaryPrincipal().toString());

        AccessToken accessToken = accessTokenBuilder.build();

        cookieIssuer.authenticate(request, response, accessToken);
    }

    /**
     * Invalidates the authentication token for the current session.
     *
     * @param request
     * @param response
     */
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Subject subject = SecurityUtils.getSubject();
        subject.logout();

        cookieIssuer.invalidate(request, response);
    }
}
