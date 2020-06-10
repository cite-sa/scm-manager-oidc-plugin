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

import de.otto.edison.hal.Links;
import gr.cite.scm.plugin.oidc.OidcAuthConfig;
import gr.cite.scm.plugin.oidc.utils.OidcConstants;
import org.mapstruct.AfterMapping;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;
import sonia.scm.api.v2.resources.LinkBuilder;
import sonia.scm.api.v2.resources.ScmPathInfoStore;
import sonia.scm.config.ConfigurationPermissions;

import javax.inject.Inject;

import static de.otto.edison.hal.Link.link;
import static de.otto.edison.hal.Links.linkingTo;

@Mapper
public abstract class OidcAuthConfigMapper {

    abstract OidcAuthConfig fromDto(OidcAuthConfigDto dto);

    @Mapping(
            target = "attributes",
            ignore = true
    )
    abstract OidcAuthConfigDto toDto(OidcAuthConfig authConfig);

    @Inject
    private ScmPathInfoStore scmPathInfoStore;

    @AfterMapping
    void appendLinks(@MappingTarget OidcAuthConfigDto dto) {
        Links.Builder linksBuilder = linkingTo().self(self());
        if (ConfigurationPermissions.write(OidcConstants.OIDC_CONFIG_STORE_NAME).isPermitted()) {
            linksBuilder.single(link("update", update()));
        }
        dto.add(linksBuilder.build());
    }

    private String self() {
        return linkBuilder().method("get").parameters().href();
    }

    private String update() {
        return linkBuilder().method("update").parameters().href();
    }

    private LinkBuilder linkBuilder() {
        return new LinkBuilder(scmPathInfoStore.get(), OidcAuthConfigResource.class);
    }

}
