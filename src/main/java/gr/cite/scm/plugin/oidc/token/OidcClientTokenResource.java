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
package gr.cite.scm.plugin.oidc.token;

import com.google.inject.Inject;
import gr.cite.scm.plugin.oidc.OidcAuthConfig;
import gr.cite.scm.plugin.oidc.OidcAuthenticationHandler;
import org.apache.http.HttpStatus;
import org.apache.shiro.SecurityUtils;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.util.ArrayList;
import java.util.List;

@Path("oidc/token")
public class OidcClientTokenResource {

    private OidcClientTokenIssuer clientTokenIssuer;

    private OidcAuthenticationHandler authenticationHandler;

    @Inject
    public OidcClientTokenResource(OidcClientTokenIssuer clientTokenIssuer, OidcAuthenticationHandler authenticationHandler) {
        this.clientTokenIssuer = clientTokenIssuer;
        this.authenticationHandler = authenticationHandler;
    }

    @GET()
    @Path("list")
    @Produces({MediaType.APPLICATION_JSON})
    public List<OidcClientTokensStore.Token> getUserTokens() {
        if (!authenticationHandler.getConfig().getEnabled() || !authenticationHandler.getConfig().getAuthenticationFlow().equals(OidcAuthConfig.AuthenticationFlow.IDENTIFICATION_TOKEN)) {
            return new ArrayList<>();
        }
        return clientTokenIssuer.getUserTokens(getSubject());
    }

    @GET()
    @Path("issue")
    @Produces({MediaType.APPLICATION_JSON})
    public Object issue(@QueryParam("length") String length) {
        if (!authenticationHandler.getConfig().getEnabled() || !authenticationHandler.getConfig().getAuthenticationFlow().equals(OidcAuthConfig.AuthenticationFlow.IDENTIFICATION_TOKEN)) {
            return Response.status(HttpStatus.SC_FORBIDDEN).build();
        }
        OidcClientTokensStore.Token token;
        if (length != null) {
            try {
                token = clientTokenIssuer.issue(getSubject(), Long.parseLong(length));
            } catch (NumberFormatException e) {
                return Response.status(HttpStatus.SC_FORBIDDEN).build();
            }
        } else {
            token = clientTokenIssuer.issue(getSubject());
        }
        return new IssuedTokenResponse(token.getRawBody(), token);
    }

    @GET()
    @Path("invalidate")
    @Produces({MediaType.TEXT_PLAIN})
    public String invalidate(@QueryParam("id") String id) {
        if (!authenticationHandler.getConfig().getEnabled() || !authenticationHandler.getConfig().getAuthenticationFlow().equals(OidcAuthConfig.AuthenticationFlow.IDENTIFICATION_TOKEN)) {
            return "Forbidden";
        }
        if (id != null) {
            clientTokenIssuer.invalidate(id);
            return "OK";
        } else {
            return "Missing id argument";
        }
    }

    @GET()
    @Path("config")
    @Produces({MediaType.APPLICATION_JSON})
    public OidcClientTokensStore.ConfigRecord getConfig() {
        if (!authenticationHandler.getConfig().getEnabled() || !authenticationHandler.getConfig().getAuthenticationFlow().equals(OidcAuthConfig.AuthenticationFlow.IDENTIFICATION_TOKEN)) {
            return null;
        }
        return clientTokenIssuer.getConfiguration(getSubject());
    }

    @POST()
    @Path("config")
    @Consumes({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    public Response setConfig(@Context UriInfo uriInfo, OidcClientTokensStore.ConfigRecord config) {
        if (!authenticationHandler.getConfig().getEnabled() || !authenticationHandler.getConfig().getAuthenticationFlow().equals(OidcAuthConfig.AuthenticationFlow.IDENTIFICATION_TOKEN)) {
            return Response.status(HttpStatus.SC_FORBIDDEN).build();
        }
        if (config.getLifetime() >= 0) {
            clientTokenIssuer.saveConfiguration(config.getLifetime(), getSubject());
            return Response.created(uriInfo.getRequestUri()).build();
        } else {
            return Response.status(HttpStatus.SC_FORBIDDEN).build();
        }
    }

    /**
     * Helper method to get the currently logged in user.
     *
     * @return The user identifier
     */
    private String getSubject() {
        return SecurityUtils.getSubject().getPrincipals().getPrimaryPrincipal().toString();
    }

    private static class IssuedTokenResponse {

        private String raw_token;
        private OidcClientTokensStore.Token token;

        public IssuedTokenResponse(String raw_token, OidcClientTokensStore.Token token) {
            this.raw_token = raw_token;
            this.token = token;
        }

        public String getRaw_token() {
            return raw_token;
        }

        public void setRaw_token(String raw_token) {
            this.raw_token = raw_token;
        }

        public OidcClientTokensStore.Token getToken() {
            return token;
        }

        public void setToken(OidcClientTokensStore.Token token) {
            this.token = token;
        }
    }

}
