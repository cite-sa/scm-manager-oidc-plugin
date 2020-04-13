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
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.config.ScmConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * Rest endpoint for handling logout requests from the user
 */
@Path("oidc/logout")
public class OidcLogoutResource {

    private Logger logger = LoggerFactory.getLogger(OidcLogoutResource.class);

    private final ScmConfiguration scmConfig;

    private final OidcProviderConfig oidcProviderConfig;

    private final OidcAuthenticationHandler authenticationHandler;

    @Inject
    public OidcLogoutResource(ScmConfiguration scmConfig, OidcProviderConfig oidcProviderConfig, OidcAuthenticationHandler authenticationHandler) {
        this.scmConfig = scmConfig;
        this.oidcProviderConfig = oidcProviderConfig;
        this.authenticationHandler = authenticationHandler;
        this.oidcProviderConfig.init();
    }

    /**
     * Performs the user logout and returns the root url.
     *
     * @param request
     * @return
     */
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public final String getOidcLogout(@Context HttpServletRequest request) {
        OidcAuthConfig oidcAuthConfig = authenticationHandler.getConfig();
        logger.debug("Destroy local session and return base url");
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        if (oidcAuthConfig.getEnabled()) {
            return oidcProviderConfig.getEndSessionEndpoint() + "?redirect_uri=" + scmConfig.getBaseUrl();
        }
        return scmConfig.getBaseUrl();
    }

}
