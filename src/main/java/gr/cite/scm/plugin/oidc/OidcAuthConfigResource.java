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
import org.apache.http.HttpStatus;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.Arrays;

/**
 * Plugin configuration rest endpoint
 */
@Path("config/auth/oidc")
public class OidcAuthConfigResource {

    @Inject
    public OidcAuthConfigResource(OidcAuthenticationHandler authenticationHandler) {
        this.authenticationHandler = authenticationHandler;
    }

    /**
     * Gets the current plugin configuration
     *
     * @return
     */
    @GET
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public OidcAuthConfig getConfig() {
        return authenticationHandler.getConfig();
    }

    /**
     * Updates the current plugin configuration
     *
     * @param uriInfo
     * @param config
     * @return
     */
    @POST
    @Consumes({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public Response setConfig(@Context UriInfo uriInfo, OidcAuthConfig config) {
        if (configIsValid(config)) {
            authenticationHandler.setConfig(config);
            authenticationHandler.storeConfig();
            return Response.created(uriInfo.getRequestUri()).build();
        } else {
            return Response.created(uriInfo.getRequestUri()).status(HttpStatus.SC_NOT_ACCEPTABLE).build();
        }
    }

    /**
     * Checks if the configuration provided from the request is valid
     *
     * @param config
     * @return
     */
    private static boolean configIsValid(OidcAuthConfig config) {
        return (config.getUserIdentifier() != null &&
                Arrays.asList(new String[]{"Username", "Email", "SubjectID"}).contains(config.getUserIdentifier()) &&
                config.getClientId() != null && config.getClientId().trim().length() > 0 &&
                config.getClientSecret() != null && config.getClientSecret().trim().length() > 0 &&
                config.getAdminRole() != null && config.getAdminRole().trim().length() > 0 &&
                config.getProviderUrl() != null && config.getProviderUrl().trim().length() > 0 &&
                config.getEnabled() != null);
    }

    private OidcAuthenticationHandler authenticationHandler;
}

