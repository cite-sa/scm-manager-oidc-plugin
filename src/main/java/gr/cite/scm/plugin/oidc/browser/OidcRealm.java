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

import gr.cite.scm.plugin.oidc.AuthenticationInfoBuilder;
import gr.cite.scm.plugin.oidc.OidcContext;
import gr.cite.scm.plugin.oidc.OidcUserContext;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.plugin.Extension;

import javax.inject.Inject;
import javax.inject.Singleton;

@Singleton
@Extension
public class OidcRealm extends AuthorizingRealm {

    private static Logger logger = LoggerFactory.getLogger(OidcRealm.class);

    private OidcContext context;
    private OidcUserContext userContext;
    private AuthenticationInfoBuilder authenticationInfoBuilder;

    @Inject
    public OidcRealm(OidcContext context, AuthenticationInfoBuilder authenticationInfoBuilder) {
        this.context = context;
        this.authenticationInfoBuilder = authenticationInfoBuilder;

        setAuthenticationTokenClass(OidcAuthenticationToken.class);
        setCredentialsMatcher(new AllowAllCredentialsMatcher());
    }

    /**
     * Sets the authentication realm for the plugin.
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (!context.get().getEnabled()) {
            logger.debug("OpenId Connect authentication is disabled, skipping realm");
            return null;
        }
        OidcAuthenticationToken token = (OidcAuthenticationToken) authenticationToken;
        userContext = token.getUserContext();
        return authenticationInfoBuilder.withUserContext(userContext).withUserAttributes(token.getUserAttributes()).build();
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        if (!context.get().getEnabled()) {
            logger.debug("OpenId Connect authentication is disabled, skipping realm");
            return null;
        }

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        if (userContext != null && userContext.isAdmin()) {
            logger.debug("Admin permission set");
            authorizationInfo.addStringPermission("*");
        }
        return authorizationInfo;
    }
}
