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
import gr.cite.scm.plugin.oidc.model.OidcTokenResponseModel;
import gr.cite.scm.plugin.oidc.token.OidcClientTokenIssuer;
import gr.cite.scm.plugin.oidc.token.OidcClientTokensStore;
import org.apache.shiro.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.SCMContextProvider;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.plugin.ext.Extension;
import sonia.scm.store.Store;
import sonia.scm.store.StoreFactory;
import sonia.scm.user.User;
import sonia.scm.user.UserManager;
import sonia.scm.web.security.AuthenticationHandler;
import sonia.scm.web.security.AuthenticationResult;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Calendar;
import java.util.Map;
import java.util.TimeZone;

/**
 * Returns the final AuthenticationResult back to AutoLoginModule
 */
@Singleton
@Extension
public class OidcAuthenticationHandler implements AuthenticationHandler {

    private static final String STORE_NAME = "oidc";

    private static final String TYPE = "Open ID";

    private OidcAuthConfig config;

    private Store<OidcAuthConfig> store;

    private ScmConfiguration scmConfig;

    private OidcClientTokenIssuer clientTokenIssuer;

    private UserManager userManager;

    private static Logger logger = LoggerFactory.getLogger(OidcAuthenticationHandler.class);

    @Inject
    public OidcAuthenticationHandler(StoreFactory storeFactory, ScmConfiguration scmConfig, OidcClientTokenIssuer clientTokenIssuer, UserManager userManager) {
        store = storeFactory.getStore(OidcAuthConfig.class, STORE_NAME);
        this.scmConfig = scmConfig;
        this.clientTokenIssuer = clientTokenIssuer;
        this.userManager = userManager;
    }

    /**
     * Returns the AuthenticationResult back to AutoLoginModule
     *
     * @param request
     * @param response
     * @param username
     * @param password
     * @return
     */
    @Override
    public AuthenticationResult authenticate(HttpServletRequest request, HttpServletResponse response, String username, String password) {
        if (config.getEnabled()) {
            if (!OidcAuthUtils.isBrowser(request)) {
                try {
                    logger.trace("Request authenticated attribute : {}", request.getAttribute("authenticated"));
                    if (OidcAuthConfig.AuthenticationFlow.IDENTIFICATION_TOKEN.equals(config.getAuthenticationFlow())) {
                        logger.debug("Using Client Identification Token authentication flow...");
                        User subject = checkClientTokenPassword(username, password);
                        if (subject != null) {
                            logger.debug("Identification token authentication succeeded.");
                            return new AuthenticationResult(subject);
                        } else {
                            logger.debug("Identification token authentication failed.");
                            return AuthenticationResult.NOT_FOUND;
                        }
                    } else {
                        if (request.getAttribute("authenticated") == null) {
                            logger.debug("Using Resource Owner Grant authentication flow...");
                            OidcAuthenticationFilter.doAuthenticate(request, response, SecurityUtils.getSubject(), OidcAuthenticationFilter.oidcProviderConfigStatic, scmConfig, getConfig(), null, username, password);
                        }
                    }
                } catch (Exception e) {
                    logger.error("Identification token authentication failed. {}", e.getMessage());
                    return AuthenticationResult.FAILED;
                }
            }
            return result(request, username);
        }
        logger.info("User " + username + " did not get authenticated by oidc plugin");
        return AuthenticationResult.NOT_FOUND;
    }

    private User checkClientTokenPassword(String username, String password) {
        logger.debug("Checking if the given password corresponds to an active issued identification token...");
        String subject = clientTokenIssuer.getUserByToken(password);
        if (subject != null) {
            logger.debug("The given password corresponds to user -> {}", subject);
            if (!subject.equals(username)) {
                logger.debug("The username does not match the token's owner. Terminating authentication process...");
                return null;
            }
            OidcClientTokensStore.ProviderToken providerTokens = clientTokenIssuer.getProviderTokens(subject);
            if (providerTokens != null) {
                logger.debug("User has provider tokens stored... Checking the tokens...");
                long accessTokenExpiresAt = providerTokens.getAccessTokenExpiresAt();
                DecodedJWT decodedRefreshToken = OidcAuthUtils.decodeJWT(providerTokens.getRefreshToken());
                if (accessTokenExpiresAt > System.currentTimeMillis()) {
                    logger.debug("Access token has not expired. User is logged in.");
                    return getClientUser(decodedRefreshToken, subject);
                } else {
                    if (decodedRefreshToken.getExpiresAt().compareTo(Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTime()) > 0) {
                        logger.debug("Access token has expired. Trying to retrieve a new one from the provider using the refresh token...");
                        try {
                            OidcTokenResponseModel responseModel = OidcHttpHandler.handleRefreshTokenRequest(OidcAuthenticationFilter.oidcProviderConfigStatic, config, providerTokens.getRefreshToken());
                            if (responseModel.getAccessToken() == null || responseModel.getRefreshToken() == null) {
                                logger.debug("Could not retrieve new access token. Terminating authentication process...");
                            } else {
                                logger.debug("Access token retrieved from provider using the stored refresh token");
                                logger.debug("Starting access token signature validation...");
                                if (OidcAuthUtils.verifyJWT(OidcAuthUtils.decodeJWT(responseModel.getAccessToken()), OidcAuthenticationFilter.oidcProviderConfigStatic.getJwksUri())) {
                                    clientTokenIssuer.saveProviderTokens(responseModel.getAccessToken(), responseModel.getRefreshToken(), subject);
                                    return getClientUser(decodedRefreshToken, subject);
                                } else {
                                    logger.debug("Could not validate new access token. Terminating authentication process...");
                                }
                            }
                        } catch (IOException e) {
                            logger.error("Could not retrieve or validate new access token. Terminating authentication process...");
                        }
                    } else {
                        logger.debug("Access token has expired. Refresh token has also expired. Cannot retrieve a new access token. User is logged out.");
                        clientTokenIssuer.removeProviderTokens(subject);
                    }
                }
            } else {
                logger.debug("There are no provider tokens stored for the user. Terminating authentication process...");
            }
        } else {
            logger.debug("The given password does not correspond to a user. Terminating authentication process...");
        }
        return null;
    }

    private User getClientUser(DecodedJWT token, String subject) {
        Map<String, String> user_attributes = OidcAuthUtils.getUserAttributesFromToken(config, token);
        User user = userManager.get(subject);
        String role = user_attributes.get("role");
        if (role != null && role.contains(config.getAdminRole())) {
            user.setAdmin(true);
        } else {
            user.setAdmin(false);
        }
        return user;
    }

    @Override
    public void close() {
    }

    /**
     * Sets the plugin configuration instance
     *
     * @param context
     */
    @Override
    public void init(SCMContextProvider context) {
        config = store.get();

        if (config == null) {
            config = new OidcAuthConfig().init();
        }
    }

    /**
     * Saves the configuration instance to store
     */
    public void storeConfig() {
        store.set(config);
        logger.info("Plugin settings got updated.");
        logger.debug(config.toString());
    }


    /**
     * Gets current configuration
     *
     * @return
     */
    public OidcAuthConfig getConfig() {
        return config;
    }

    /**
     * Gets the user type this plugin creates
     *
     * @return
     */
    public static String getUserType() {
        return TYPE;
    }

    /**
     * Updates the configuration instance
     *
     * @param config
     */
    public void setConfig(OidcAuthConfig config) {
        if (!config.getEnabled()) {
            logger.debug("Plugin got disabled... Clearing all sensitive information from store...");
            clientTokenIssuer.resetTokenStore();
        } else if (!config.getAuthenticationFlow().equals(this.config.getAuthenticationFlow()) && OidcAuthConfig.AuthenticationFlow.IDENTIFICATION_TOKEN.equals(this.config.getAuthenticationFlow())) {
            logger.debug("Authentication flow changed to '{}'... Clearing all sensitive information from store...", OidcAuthConfig.AuthenticationFlow.RESOURCE_OWNER);
            clientTokenIssuer.resetTokenStore();
        }
        this.config = config;
    }

    /**
     * Gets the user type this plugin creates
     *
     * @return
     */
    @Override
    public String getType() {
        return TYPE;
    }

    private AuthenticationResult result(HttpServletRequest request, String username) {
        User user = OidcAuthenticationContext.createOidcUser(config, request);
        if (user != null && user.isValid()) {
            logger.info("User " + username + " successfully authenticated by oidc plugin");
            AuthenticationResult result = new AuthenticationResult(user);
            result.setCacheable(false);
            return result;
        }
        return AuthenticationResult.NOT_FOUND;
    }
}
