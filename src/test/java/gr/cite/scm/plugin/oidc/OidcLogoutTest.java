/*
 * MIT License
 *
 * Copyright (c) 2020 Communication & Information Technologies Experts SA
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
package gr.cite.scm.plugin.oidc;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import gr.cite.scm.plugin.oidc.token.OidcClientTokenIssuer;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import sonia.scm.config.ScmConfiguration;

import javax.servlet.http.HttpServletRequest;

public class OidcLogoutTest {

    @Mock
    private ScmConfiguration scmConfiguration;
    @Mock
    private OidcProviderConfig oidcProviderConfig;
    @Mock
    private OidcAuthConfig oidcAuthConfig;
    @Mock
    private OidcAuthenticationHandler oidcAuthenticationHandler;
    @Mock
    private HttpServletRequest request;
    @Mock
    private SecurityManager securityManager;
    @Mock
    private OidcClientTokenIssuer clientTokenIssuer;
    @Mock
    private Subject subject;
    @Mock
    private PrincipalCollection principalCollection;

    @InjectMocks
    private OidcLogoutResource oidcLogoutResource;

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        when(subject.isAuthenticated()).thenReturn(true);
        when(subject.getPrincipals()).thenReturn(principalCollection);
        when(principalCollection.getPrimaryPrincipal()).thenReturn("subject");
        ThreadContext.bind(subject);
        ThreadContext.bind(securityManager);
        when(oidcAuthConfig.getEnabled()).thenReturn(true);
        when(oidcAuthenticationHandler.getConfig()).thenReturn(oidcAuthConfig);
    }

    @After
    public void cleanup() {
        ThreadContext.unbindSubject();
        ThreadContext.unbindSecurityManager();
    }

    @Test
    public void shouldReturnLogoutUrl() {
        assertEquals("Failure - The logout url is not correct...", logoutUrl(), oidcLogoutResource.getOidcLogout(request));
        verify(subject, atLeastOnce()).logout();
    }

    private String logoutUrl() {
        return oidcProviderConfig.getEndSessionEndpoint() + "?redirect_uri=" + scmConfiguration.getBaseUrl();
    }

}
