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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.user.User;

import java.util.Map;

/**
 * Authentication Context helper class. Responsible for creating the User objects
 */
public class OidcUserContext {

    private User user = null;
    private boolean admin = false;

    private static Logger logger = LoggerFactory.getLogger(OidcUserContext.class);

    /**
     * Sets basic information for the user.
     *
     * @param identifier
     * @param displayName
     * @param mail
     * @return
     */
    private User createUser(final String identifier, final String displayName, final String mail) {
        User user = new User();
        user.setName(identifier);
        user.setDisplayName(displayName);
        user.setMail(mail);
        user.setPassword(null);
        user.setType(OidcConstants.USER_TYPE);

        logger.info("User {} successfully created by Oidc plugin", identifier);
        return user;
    }

    /**
     * Finalises and returns the User object for the login process.
     *
     * @param config
     * @param attributes
     * @return
     */
    public User createOidcUser(OidcAuthConfig config, final Map<String, String> attributes) {
        User user = null;
        try {
            if (attributes != null) {
                String username = attributes.get("username");
                String display_name = attributes.get("display_name");
                String email = attributes.get("email");
                String subject_id = attributes.get("sub");

                boolean usesEmailIdentifier = "Email".equals(config.getUserIdentifier());
                boolean usesUsernameIdentifier = "Username".equals(config.getUserIdentifier());
                boolean usesSubjectIdIdentifier = "SubjectID".equals(config.getUserIdentifier());

                boolean isUsernameDefined = username != null && !username.trim().isEmpty();
                boolean isDisplayNameDefined = display_name != null && !display_name.trim().isEmpty();
                boolean isEmailDefined = email != null && !email.trim().isEmpty();
                boolean isSubjectIdDefined = subject_id != null && !subject_id.trim().isEmpty();

                if (usesEmailIdentifier && isEmailDefined && isDisplayNameDefined) {
                    user = createUser(email, display_name, email);
                } else if (usesUsernameIdentifier && isUsernameDefined && isDisplayNameDefined && isEmailDefined) {
                    user = createUser(username, display_name, email);
                } else if (usesSubjectIdIdentifier && isSubjectIdDefined && isDisplayNameDefined && isEmailDefined) {
                    user = createUser(subject_id, display_name, email);
                } else {
                    return null;
                }

                String role = attributes.get("role");
                admin = role != null && role.contains(config.getAdminRole());
            }
        } catch (Exception e) {
            logger.error("Error while creating a user : {}", e.getMessage());
        }
        this.user = user;
        return user;
    }

    /**
     * Returns the final user object.
     *
     * @return
     */
    public User getUser() {
        return user;
    }

    /**
     * Returns true if the user has admin privileges.
     *
     * @return
     */
    public boolean isAdmin() {
        return admin;
    }

}
