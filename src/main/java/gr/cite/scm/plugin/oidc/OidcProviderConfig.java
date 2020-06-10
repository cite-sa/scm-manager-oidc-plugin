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
package gr.cite.scm.plugin.oidc;

import com.google.inject.Inject;
import gr.cite.scm.plugin.oidc.model.OidcProviderConfigModel;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Singleton;
import java.io.IOException;

/**
 * Configuration for the OpenID Provider.
 */
@Singleton
public class OidcProviderConfig {

    private Logger logger = LoggerFactory.getLogger(OidcProviderConfig.class);

    private String authorizationEndpoint, tokenEndpoint, endSessionEndpoint, jwksUri;

    private OidcContext context;

    private boolean initialized = false;

    @Inject
    public OidcProviderConfig(OidcContext context) {
        this.context = context;
    }

    /**
     * Gets the provider endpoints from the given .well-known uri.
     */
    public OidcProviderConfig init() {
        OidcAuthConfig authConfig = context.get();
        if (!initialized && authConfig.getEnabled()) {
            try {
                logger.info("Setting up provider configuration...");
                CloseableHttpClient httpClient = HttpClients.createDefault();
                HttpGet get = new HttpGet(authConfig.getProviderUrl());
                String resStr = EntityUtils.toString(httpClient.execute(get).getEntity());
                get.releaseConnection();
                httpClient.close();
                logger.info("Request to get provider endpoints completed.");
                OidcProviderConfigModel model = OidcAuthUtils.parseJSON(resStr, OidcProviderConfigModel.class);
                logger.debug("JSON response parsed. Extracted values:");
                this.authorizationEndpoint = model.getAuthorization_endpoint();
                logger.debug("authorization_endpoint -> {}", this.authorizationEndpoint);
                this.tokenEndpoint = model.getToken_endpoint();
                logger.debug("token_endpoint -> {}", this.tokenEndpoint);
                this.endSessionEndpoint = model.getEnd_session_endpoint();
                logger.debug("end_session_endpoint -> {}", this.endSessionEndpoint);
                this.jwksUri = model.getJwks_uri();
                logger.debug("jwks_uri -> {}", this.jwksUri);
                this.initialized = true;
            } catch (IOException e) {
                logger.error("Error while setting up provider configuration : {}", e.getMessage());
            }
        }
        return this;
    }

    public OidcProviderConfig reset() {
        this.initialized = false;
        return this;
    }

    public String getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public String getEndSessionEndpoint() {
        return endSessionEndpoint;
    }

    public String getJwksUri() {
        return jwksUri;
    }
}
