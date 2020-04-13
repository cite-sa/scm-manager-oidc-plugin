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

import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.plugin.ext.Extension;
import sonia.scm.user.*;
import sonia.scm.util.HttpUtil;
import sonia.scm.web.filter.AutoLoginModule;
import sonia.scm.web.filter.AutoLoginModules;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * Login Interceptor, implements AutoLoginModule. Plugin Extension Point
 */
@Singleton
@Extension
public class OidcAuthenticationFilter implements AutoLoginModule {

    private static final Logger logger = LoggerFactory.getLogger(OidcAuthenticationFilter.class);

    private final ScmConfiguration scmConfig;

    private final OidcAuthenticationHandler authenticationHandler;

    private final OidcProviderConfig oidcProviderConfig;

    @Inject
    public OidcAuthenticationFilter(ScmConfiguration scmConfig, OidcAuthenticationHandler authenticationHandler, OidcProviderConfig oidcProviderConfig) {
        this.scmConfig = scmConfig;
        this.authenticationHandler = authenticationHandler;
        this.oidcProviderConfig = oidcProviderConfig;
        this.oidcProviderConfig.init();
    }

    /**
     * Handles the OpenID Authentication process
     *
     * @param httpServletRequest
     * @param httpServletResponse
     * @param subject
     * @return
     */
    @Override
    public User authenticate(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Subject subject) {
        User user = null;
        OidcAuthConfig authConfig = authenticationHandler.getConfig();
        if (authConfig.getEnabled() && !subject.isAuthenticated() && !httpServletRequest.getRequestURI().contains("/resources")) {
            logger.info("Auth plugin is enabled.");
            try {
                if (httpServletRequest.getParameterMap().containsKey("code")) {
                    logger.info("Starting Open ID Authentication process...");
                    String code = httpServletRequest.getParameter("code").trim();
                    logger.info("Redirected back to root with code -> ************");

                    String access_token = OidcHttpHandler.handleTokenRequest(code, oidcProviderConfig, authConfig, scmConfig);
                    if (access_token == null) {
                        logger.info("No access_token received... Authentication process failed.");
                        sendRedirect(httpServletRequest, httpServletResponse, httpServletRequest.getContextPath());
                    }

                    DecodedJWT jwt = OidcAuthUtils.decodeJWT(access_token);
                    if (jwt == null) {
                        logger.info("JWT is not valid... Authentication process failed.");
                        sendRedirect(httpServletRequest, httpServletResponse, httpServletRequest.getContextPath());
                    }

                    Map<String, String> user_attributes = OidcAuthUtils.getUserAttributesFromToken(authConfig, Objects.requireNonNull(jwt));

                    if (OidcAuthUtils.verifyJWT(jwt, oidcProviderConfig.getJwksUri())) {
                        user = completeAuthenticationProcess(authConfig, user_attributes, httpServletRequest, httpServletResponse, subject);
                    }else{
                        logger.info("JWT is not valid... Authentication process failed.");
                        sendRedirect(httpServletRequest, httpServletResponse, httpServletRequest.getContextPath());
                    }
                } else if (OidcAuthUtils.isBrowser(httpServletRequest)) {
                    sendRedirect(httpServletRequest, httpServletResponse, getProviderCodeRequestString());
                }
            } catch (IOException e) {
                logger.error("Error while trying OpenID authentication : {}", e.getMessage());
            }
        }
        return user;
    }

    /**
     * Completes the authentication process by logging the user in and redirecting to root.
     *
     * @param authConfig
     * @param user_attributes
     * @param httpServletRequest
     * @param httpServletResponse
     * @param subject
     * @return
     */
    private User completeAuthenticationProcess(OidcAuthConfig authConfig, Map<String, String> user_attributes, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Subject subject) {
        User user;
        httpServletRequest.setAttribute("user_attributes", user_attributes);
        if (authConfig.getUserIdentifier().equals("Email")) {
            user = getLoginUser(subject, httpServletRequest.getRemoteAddr(), user_attributes.get("email"));
        } else if (authConfig.getUserIdentifier().equals("Username")) {
            user = getLoginUser(subject, httpServletRequest.getRemoteAddr(), user_attributes.get("username"));
        } else {
            user = getLoginUser(subject, httpServletRequest.getRemoteAddr(), user_attributes.get("sub"));
        }
        if (user != null && httpServletRequest.getQueryString() != null) {
            logger.info("Redirecting after successful validation.");
            sendRedirect(httpServletRequest, httpServletResponse, httpServletRequest.getContextPath());
        }
        return user;
    }

    /**
     * Generates the code request url
     *
     * @return
     */
    private String getProviderCodeRequestString() {
        OidcAuthConfig authConfig = authenticationHandler.getConfig();
        return oidcProviderConfig.getAuthorizationEndpoint() + "?" +
                "client_id=" + authConfig.getClientId() +
                "&redirect_uri=" + scmConfig.getBaseUrl() +
                "&scope=openid profile email phone address roles" +
                "&response_type=code" +
                "&state=" + UUID.randomUUID().toString().replace("-", "");
    }

    /**
     * Handles the redirection to the provider authentication endpoint
     *
     * @param request
     * @param response
     * @param location
     */
    public void sendRedirect(final HttpServletRequest request, final HttpServletResponse response, final String location) {
        try {
            if (HttpUtil.isWUIRequest(request)) {
                AutoLoginModules.markAsComplete(request);
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            } else {
                AutoLoginModules.sendRedirect(request, response, location);
            }
        } catch (IllegalStateException | IOException e) {
            logger.error("Cannot send redirect : {}", e.getMessage());
        }
    }

    /**
     * Gets the User object as it got returned from the login process.
     *
     * @param subject
     * @param remoteAddr
     * @param username
     * @return
     */
    private User getLoginUser(final Subject subject, final String remoteAddr, final String username) {
        return tryLogin(subject, createToken(username, remoteAddr));
    }

    private AuthenticationToken createToken(String username, String remoteAddr) {
        return new UsernamePasswordToken(username, UUID.randomUUID().toString(), remoteAddr);
    }

    /**
     * Calls the Login function and returns the User object.
     *
     * @param subject
     * @param token
     * @return
     */
    private User tryLogin(final Subject subject, final AuthenticationToken token) {
        OidcAuthConfig authConfig = authenticationHandler.getConfig();
        User user = null;
        try {
            logger.debug("Login attempting...");
            subject.login(token);
            user = subject.getPrincipals().oneByType(User.class);
            if (user.getCreationDate() != null && authConfig.getEnabled()) {
                logger.debug("New user registered from OpenID provider.");
            }
        } catch (AuthenticationException e) {
            logger.error("AuthenticationException while trying to login the user : {}", e.getMessage());
        }
        return user;
    }
}