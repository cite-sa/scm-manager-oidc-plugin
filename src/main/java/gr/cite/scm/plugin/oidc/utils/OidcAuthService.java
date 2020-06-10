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
package gr.cite.scm.plugin.oidc.utils;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.inject.Inject;
import gr.cite.scm.plugin.oidc.*;
import gr.cite.scm.plugin.oidc.browser.OidcAuthenticationToken;
import gr.cite.scm.plugin.oidc.browser.OidcLoginHandler;
import org.apache.shiro.authc.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.config.ScmConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Objects;

public class OidcAuthService {

    private static Logger logger = LoggerFactory.getLogger(OidcAuthService.class);

    private ScmConfiguration scmConfig;
    private OidcContext context;
    private OidcUserContext userContext;
    private OidcProviderConfig providerConfig;
    private OidcLoginHandler loginHandler;

    private Map<String, String> user_attributes;
    private String access_token;

    @Inject
    public OidcAuthService(ScmConfiguration scmConfig, OidcContext context, OidcUserContext userContext, OidcProviderConfig providerConfig, OidcLoginHandler loginHandler) {
        this.scmConfig = scmConfig;
        this.context = context;
        this.userContext = userContext;
        this.providerConfig = providerConfig;
        this.loginHandler = loginHandler;
    }

    /**
     * Initiates authentication using the code provider flow.
     *
     * @param code
     * @return
     * @throws IOException
     */
    public boolean authenticateWithCode(String code) throws IOException {
        access_token = OidcHttpHandler.handleTokenRequest(code, providerConfig, context.get(), scmConfig);
        return authenticate();
    }

    /**
     * Intiates authentication using the direct grant provider flow.
     *
     * @param username
     * @param password
     * @return
     * @throws IOException
     */
    public boolean authenticateWithPassword(String username, String password) throws IOException {
        access_token = OidcHttpHandler.handlePasswordTokenRequest(providerConfig, context.get(), username, password);
        return authenticate();
    }

    /**
     * Helper method to avoid code duplication
     *
     * @return
     */
    private boolean authenticate() {
        if (access_token == null) {
            logger.info("No access_token received... Authentication process failed.");
            return false;
        }

        DecodedJWT jwt = OidcAuthUtils.decodeJWT(access_token);
        if (jwt == null) {
            logger.info("JWT is not valid... Authentication process failed.");
            return false;
        }

        user_attributes = OidcAuthUtils.getUserAttributesFromToken(context.get(), Objects.requireNonNull(jwt));

        if (OidcAuthUtils.verifyJWT(jwt, providerConfig.getJwksUri())) {
            return true;
        } else {
            logger.info("JWT is not valid... Authentication process failed.");
            return false;
        }
    }

    /**
     * Completes the authentication process by logging the user in.
     *
     * @param request
     * @param response
     * @return
     */
    public boolean completeAuthenticationProcess(HttpServletRequest request, HttpServletResponse response) {
        try {
            loginHandler.login(request, response, OidcAuthenticationToken.get(access_token).withUserContext(userContext).withUserAttributes(user_attributes));
            return true;
        } catch (AuthenticationException e) {
            logger.error("Login failed...");
            return false;
        }
    }

    public String getAccessToken() {
        return access_token;
    }

    public Map<String, String> getUserAttributes() {
        return this.user_attributes;
    }

}
