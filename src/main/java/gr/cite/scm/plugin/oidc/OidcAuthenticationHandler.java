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

import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.servlet.SessionScoped;
import org.apache.shiro.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.SCMContextProvider;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.plugin.ext.Extension;
import sonia.scm.store.Store;
import sonia.scm.store.StoreFactory;
import sonia.scm.user.User;
import sonia.scm.web.security.AuthenticationHandler;
import sonia.scm.web.security.AuthenticationResult;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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

    private static Logger logger = LoggerFactory.getLogger(OidcAuthenticationHandler.class);

    @Inject
    public OidcAuthenticationHandler(StoreFactory storeFactory, ScmConfiguration scmConfig) {
        store = storeFactory.getStore(OidcAuthConfig.class, STORE_NAME);
        this.scmConfig = scmConfig;
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
            if (OidcAuthUtils.isBrowser(request)) {
                return result(request, username);
            } else {
                try {
                    logger.trace("Request authenticated attribute : {}", request.getAttribute("authenticated"));
                    if (request.getAttribute("authenticated") == null) {
                        OidcAuthenticationFilter.doAuthenticate(request, response, SecurityUtils.getSubject(), OidcAuthenticationFilter.oidcProviderConfigStatic, scmConfig, getConfig(), username, password);
                    }
                } catch (IOException e) {
                    return AuthenticationResult.FAILED;
                }
                return result(request, username);
            }
        }
        logger.info("User " + username + " did not get authenticated by oidc plugin");
        return AuthenticationResult.NOT_FOUND;
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
