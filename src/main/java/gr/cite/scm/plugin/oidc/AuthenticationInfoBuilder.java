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

import gr.cite.scm.plugin.oidc.utils.OidcConstants;
import org.apache.shiro.authc.AuthenticationInfo;
import sonia.scm.group.Group;
import sonia.scm.group.GroupManager;
import sonia.scm.security.AssignedPermission;
import sonia.scm.security.SecuritySystem;
import sonia.scm.security.SyncingRealmHelper;
import sonia.scm.user.User;
import sonia.scm.web.security.AdministrationContext;

import javax.inject.Inject;
import java.util.Map;
import java.util.Objects;

public class AuthenticationInfoBuilder {

    private final SyncingRealmHelper syncingRealmHelper;
    private OidcContext context;
    private OidcUserContext userContext;
    private GroupManager groupManager;
    private AdministrationContext administrationContext;
    private SecuritySystem securitySystem;
    private Map<String, String> user_attributes;

    @Inject
    public AuthenticationInfoBuilder(OidcContext context, SyncingRealmHelper syncingRealmHelper, GroupManager groupManager, AdministrationContext administrationContext, SecuritySystem securitySystem) {
        this.syncingRealmHelper = syncingRealmHelper;
        this.context = context;
        this.groupManager = groupManager;
        this.administrationContext = administrationContext;
        this.securitySystem = securitySystem;
    }

    /**
     * Creates and returns the AuthenticationInfo object for the register and login completion.
     *
     * @return
     */
    public AuthenticationInfo build() {
        if (userContext == null) {
            return null;
        }
        User user = user_attributes != null ? userContext.createOidcUser(context.get(), user_attributes) : null;
        if (user != null) {
            syncingRealmHelper.store(user);
            if (userContext.isAdmin()) {
                administrationContext.runAsAdmin(() -> {
                    securitySystem.addPermission(new AssignedPermission(Objects.requireNonNull(user).getId(), false, "*"));
                    Group group = groupManager.get(OidcConstants.ADMIN_GROUP_NAME);
                    if (group == null) {
                        Group new_group = new Group();
                        new_group.setName(OidcConstants.ADMIN_GROUP_NAME);
                        new_group.setType(OidcConstants.USER_TYPE);
                        new_group.setDescription(OidcConstants.ADMIN_GROUP_DESC);
                        new_group.add(user.getName());
                        syncingRealmHelper.store(new_group);
                        securitySystem.addPermission(new AssignedPermission(Objects.requireNonNull(new_group).getId(), true, "*"));
                    } else {
                        group.add(user.getName());
                        syncingRealmHelper.store(group);
                    }
                });
            }
            return syncingRealmHelper.createAuthenticationInfo(OidcConstants.OIDC_CONFIG_STORE_NAME, user);
        } else return null;
    }

    /**
     * Sets the UserContext instance.
     *
     * @param userContext
     * @return
     */
    public AuthenticationInfoBuilder withUserContext(OidcUserContext userContext) {
        this.userContext = userContext;
        return this;
    }

    /**
     * Sets the user attributes map.
     *
     * @param user_attributes
     * @return
     */
    public AuthenticationInfoBuilder withUserAttributes(Map<String, String> user_attributes) {
        this.user_attributes = user_attributes;
        return this;
    }

}
