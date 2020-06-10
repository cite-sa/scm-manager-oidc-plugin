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

import gr.cite.scm.plugin.oidc.*;
import gr.cite.scm.plugin.oidc.utils.OidcAuthService;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.api.v2.resources.ErrorDto;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.security.AllowAnonymousAccess;
import sonia.scm.web.VndMediaType;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;

@Singleton
@OpenAPIDefinition(tags = {@Tag(name = "OpenId Connect Plugin")})
@AllowAnonymousAccess
@Path(OidcAuthenticationResource.PATH)
public class OidcAuthenticationResource {

    private static Logger logger = LoggerFactory.getLogger(OidcAuthenticationResource.class);

    public static final String PATH = "v2/oidc/auth";

    private ScmConfiguration scmConfig;
    private OidcContext context;
    private OidcProviderConfig providerConfig;

    private OidcAuthService authService;
    private OidcLoginHandler loginHandler;

    @Inject
    public OidcAuthenticationResource(ScmConfiguration scmConfig, OidcContext context, OidcProviderConfig providerConfig, OidcAuthService authService, OidcLoginHandler loginHandler) {
        this.scmConfig = scmConfig;
        this.context = context;
        this.providerConfig = providerConfig;
        this.authService = authService;
        this.loginHandler = loginHandler;
    }

    @GET
    @Path("")
    @Operation(summary = "OpenId Connect login", description = "Login with OpenId Connect", tags = "OpenId Connect Plugin")
    @ApiResponse(responseCode = "200", description = "success")
    @ApiResponse(
            responseCode = "500",
            description = "internal server error",
            content = @Content(
                    mediaType = VndMediaType.ERROR_TYPE,
                    schema = @Schema(implementation = ErrorDto.class)
            )
    )
    public Response login(@Context HttpServletRequest request,
                          @Context HttpServletResponse response,
                          @QueryParam("code") String code) throws IOException {
        logger.info("Received request to {} with code -> {}", request.getRequestURI(), code);
        if (authService.authenticateWithCode(code)) {
            if (authService.completeAuthenticationProcess(request, response)) {
                return Response.seeOther(URI.create(scmConfig.getBaseUrl())).build();
            }
        }
        return Response.status(HttpStatus.SC_UNAUTHORIZED, "Authentication was not possible...").build();
    }

    @GET
    @Path("logout")
    @Operation(summary = "OpenId Connect logout", description = "Logout from OpenId Connect", tags = "OpenId Connect Plugin")
    @ApiResponse(responseCode = "200", description = "success")
    @ApiResponse(
            responseCode = "500",
            description = "internal server error",
            content = @Content(
                    mediaType = VndMediaType.ERROR_TYPE,
                    schema = @Schema(implementation = ErrorDto.class)
            )
    )
    public Response logout(@Context HttpServletRequest request,
                           @Context HttpServletResponse response) {
        loginHandler.logout(request, response);
        String providerLogoutUrl = providerConfig.getEndSessionEndpoint() + "?redirect_uri=" + scmConfig.getBaseUrl();

        if (context.get().getEnabled()) {
            return Response.ok(providerLogoutUrl, MediaType.TEXT_PLAIN).build();
        } else {
            return Response.ok(scmConfig.getBaseUrl(), MediaType.TEXT_PLAIN_TYPE).build();
        }
    }

}
