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

import gr.cite.scm.plugin.oidc.model.OidcTokenResponseModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.config.ScmConfiguration;

import java.io.IOException;

/**
 * Helper class for abstracting complex response handling.
 */
public class OidcHttpHandler {

    private static Logger logger = LoggerFactory.getLogger(OidcHttpHandler.class);

    /**
     * Sends a request to the token endpoint and handles the response by returning the access token from the provider.
     *
     * @param code
     * @param oidcProviderConfig
     * @param authConfig
     * @param scmConfig
     * @return
     * @throws IOException
     */
    public static OidcTokenResponseModel handleTokenRequest(String code, OidcProviderConfig oidcProviderConfig, OidcAuthConfig authConfig, ScmConfiguration scmConfig) throws IOException {
        logger.debug("Started preparing access token request...");
        String resStr = OidcAuthUtils.sendTokenRequest(oidcProviderConfig, authConfig, scmConfig, code);
        logger.debug("Request completed with JSON response -> *************");

        OidcTokenResponseModel model = OidcAuthUtils.parseJSON(resStr, OidcTokenResponseModel.class);
        logger.debug("JSON response parsed. Extracted values:");
        String access_token = model == null ? "" : model.getAccessToken();
        logger.debug("access_token -> ************");
        String refresh_token = model == null ? "" : model.getRefreshToken();
        logger.debug("refresh_token -> ************");
        if (access_token.equals("") || refresh_token.equals("")) {
            return new OidcTokenResponseModel();
        }
        return model;
    }

    /**
     * Sends a request to the token endpoint using password credentials and handles the response by returning the access token from the provider.
     *
     * @param providerConfig
     * @param authConfig
     * @param username
     * @param password
     * @return
     * @throws IOException
     */
    public static OidcTokenResponseModel handlePasswordTokenRequest(OidcProviderConfig providerConfig, OidcAuthConfig authConfig, String username, String password) throws IOException {
        logger.debug("Started preparing password access token request...");
        String resStr = OidcAuthUtils.sendPasswordTokenRequest(providerConfig, authConfig, username, password);
        logger.debug("Request completed with JSON response -> *************");

        OidcTokenResponseModel model = OidcAuthUtils.parseJSON(resStr, OidcTokenResponseModel.class);
        logger.debug("JSON response parsed. Extracted values:");
        String access_token = model == null ? "" : model.getAccessToken();
        logger.debug("access_token -> ************");
        String refresh_token = model == null ? "" : model.getRefreshToken();
        logger.debug("refresh_token -> ************");
        if (access_token.equals("") || refresh_token.equals("")) {
            return new OidcTokenResponseModel();
        }
        return model;
    }

    /**
     * Sends a request to the token endpoint using refresh_token and handles the response by returning the access token from the provider.
     *
     * @param providerConfig
     * @param authConfig
     * @param given_refresh_token
     * @return
     * @throws IOException
     */
    public static OidcTokenResponseModel handleRefreshTokenRequest(OidcProviderConfig providerConfig, OidcAuthConfig authConfig, String given_refresh_token) throws IOException {
        logger.debug("Started preparing refresh token request...");
        String resStr = OidcAuthUtils.sendRefreshTokenRequest(providerConfig, authConfig, given_refresh_token);
        logger.debug("Request completed with JSON response -> *************");

        OidcTokenResponseModel model = OidcAuthUtils.parseJSON(resStr, OidcTokenResponseModel.class);
        logger.debug("JSON response parsed. Extracted values:");
        String access_token = model == null ? "" : model.getAccessToken();
        logger.debug("access_token -> ************");
        String refresh_token = model == null ? "" : model.getRefreshToken();
        logger.debug("refresh_token -> ************");
        if (access_token.equals("") || refresh_token.equals("")) {
            return new OidcTokenResponseModel();
        }
        return model;
    }

}
