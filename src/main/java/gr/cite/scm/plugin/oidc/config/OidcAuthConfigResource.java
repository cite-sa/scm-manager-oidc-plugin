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
package gr.cite.scm.plugin.oidc.config;

import com.google.inject.Inject;
import gr.cite.scm.plugin.oidc.OidcAuthConfig;
import gr.cite.scm.plugin.oidc.utils.OidcConstants;
import gr.cite.scm.plugin.oidc.OidcContext;
import gr.cite.scm.plugin.oidc.OidcProviderConfig;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import sonia.scm.api.v2.resources.ErrorDto;
import sonia.scm.config.ConfigurationPermissions;
import sonia.scm.group.Group;
import sonia.scm.group.GroupManager;
import sonia.scm.security.AssignedPermission;
import sonia.scm.security.SecuritySystem;
import sonia.scm.web.VndMediaType;
import sonia.scm.web.security.AdministrationContext;

import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import java.util.Objects;

@Path(OidcAuthConfigResource.PATH)
public class OidcAuthConfigResource {

    private static final String CONTENT_TYPE = VndMediaType.PREFIX + "oidcConfig" + VndMediaType.SUFFIX;

    public static final String PATH = "v2/config/oidc";

    private final OidcContext context;
    private final OidcAuthConfigMapper mapper;
    private OidcProviderConfig providerConfig;
    private GroupManager groupManager;
    private AdministrationContext administrationContext;
    private SecuritySystem securitySystem;

    @Inject
    public OidcAuthConfigResource(OidcContext context, OidcAuthConfigMapper mapper, OidcProviderConfig providerConfig, GroupManager groupManager, AdministrationContext administrationContext, SecuritySystem securitySystem) {
        this.context = context;
        this.mapper = mapper;
        this.providerConfig = providerConfig;
        this.groupManager = groupManager;
        this.administrationContext = administrationContext;
        this.securitySystem = securitySystem;
    }

    @GET
    @Path("")
    @Produces(CONTENT_TYPE)
    @Operation(summary = "Get oidc configuration", description = "Returns the oidc configuration.", tags = "OpenID Connect Plugin")
    @ApiResponse(
            responseCode = "200",
            description = "success",
            content = @Content(
                    mediaType = CONTENT_TYPE,
                    schema = @Schema(implementation = OidcAuthConfigDto.class)
            )
    )
    @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
    @ApiResponse(responseCode = "403", description = "not authorized /  the current user does not have the \"configuration:read:oidc\" privilege")
    @ApiResponse(
            responseCode = "500",
            description = "internal server error",
            content = @Content(
                    mediaType = VndMediaType.ERROR_TYPE,
                    schema = @Schema(implementation = ErrorDto.class)
            )
    )
    public OidcAuthConfigDto get() {
        ConfigurationPermissions.read(OidcConstants.OIDC_CONFIG_STORE_NAME).check();
        OidcAuthConfig authConfig = context.get();
        return mapper.toDto(authConfig);
    }

    @PUT
    @Path("")
    @Consumes(CONTENT_TYPE)
    @Operation(summary = "Update oidc configuration", description = "Modifies the oidc configuration.", tags = "OpenID Connect Plugin")
    @ApiResponse(responseCode = "204", description = "update success")
    @ApiResponse(responseCode = "401", description = "not authenticated / invalid credentials")
    @ApiResponse(responseCode = "403", description = "not authorized /  the current user does not have the \"configuration:write:oidc\" privilege")
    @ApiResponse(
            responseCode = "500",
            description = "internal server error",
            content = @Content(
                    mediaType = VndMediaType.ERROR_TYPE,
                    schema = @Schema(implementation = ErrorDto.class)
            )
    )
    public Response update(OidcAuthConfigDto dto) {
        ConfigurationPermissions.write(OidcConstants.OIDC_CONFIG_STORE_NAME).check();
        OidcAuthConfig authConfig = mapper.fromDto(dto);
        context.set(authConfig);
        providerConfig.reset().init();
        administrationContext.runAsAdmin(() -> {
            if (groupManager.get(OidcConstants.ADMIN_GROUP_NAME) == null) {
                Group group = new Group();
                group.setName(OidcConstants.ADMIN_GROUP_NAME);
                group.setType(OidcConstants.USER_TYPE);
                group.setDescription(OidcConstants.ADMIN_GROUP_DESC);
                groupManager.create(group);
                securitySystem.addPermission(new AssignedPermission(Objects.requireNonNull(group).getId(), true, "*"));
            }
        });
        return Response.noContent().build();
    }

}
