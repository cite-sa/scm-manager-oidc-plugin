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
package gr.cite.scm.plugin.oidc.rest;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import gr.cite.scm.plugin.oidc.AuthenticationInfoBuilder;
import gr.cite.scm.plugin.oidc.utils.OidcAuthService;
import gr.cite.scm.plugin.oidc.OidcContext;
import gr.cite.scm.plugin.oidc.OidcUserContext;
import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.plugin.Extension;

import java.io.IOException;

@Singleton
@Extension
public class OidcRestRealm extends AuthorizingRealm {

    private static Logger logger = LoggerFactory.getLogger(OidcRestRealm.class);

    private final OidcContext context;
    private OidcUserContext userContext;
    private final OidcAuthService authService;
    private final AuthenticationInfoBuilder authenticationInfoBuilder;

    @Inject
    public OidcRestRealm(OidcContext context, OidcUserContext userContext, OidcAuthService authService, AuthenticationInfoBuilder authenticationInfoBuilder) {
        this.context = context;
        this.userContext = userContext;
        this.authService = authService;
        this.authenticationInfoBuilder = authenticationInfoBuilder;

        setAuthenticationTokenClass(UsernamePasswordToken.class);
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        if (!context.get().getEnabled()) {
            return null;
        }
        return new SimpleAuthorizationInfo();
    }

    /**
     * Sets the client authentication Realm for the plugin.
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (!context.get().getEnabled()) {
            return null;
        }
        UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
        try {
            if (authService.authenticateWithPassword(token.getUsername(), String.valueOf(token.getPassword()))) {
                return authenticationInfoBuilder.withUserAttributes(authService.getUserAttributes()).withUserContext(userContext).build();
            }
            return null;
        } catch (IOException e) {
            logger.error("Authentication with username and password credentials failed : {}", e.getMessage());
            return null;
        }
    }
}
