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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.user.User;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Authentication Context helper class. Responsible for creating the User objects
 */
public class OidcAuthenticationContext {

    private static Logger logger = LoggerFactory.getLogger(OidcAuthenticationContext.class);

    /**
     * Sets basic information for the user.
     *
     * @param identifier
     * @param displayName
     * @param mail
     * @return
     */
    public static User createUser(final String identifier, final String displayName, final String mail) {
        User user = new User();
        user.setName(identifier);
        user.setDisplayName(displayName);
        user.setMail(mail);
        user.setPassword(null);
        user.setType(OidcAuthenticationHandler.getUserType());

        logger.info("User {} successfully created by Oidc plugin", identifier);
        return user;
    }

    /**
     * Finalises and returns the User object for the login process.
     *
     * @param config
     * @param request
     * @return
     */
    public static User createOidcUser(OidcAuthConfig config, final HttpServletRequest request) {
        User user = null;
        try {
            @SuppressWarnings("unchecked")
            Map<String, String> attributes = (Map<String, String>) request.getAttribute("user_attributes");
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
                    user = OidcAuthenticationContext.createUser(email, display_name, email);
                } else if (usesUsernameIdentifier && isUsernameDefined && isDisplayNameDefined && isEmailDefined) {
                    user = OidcAuthenticationContext.createUser(username, display_name, email);
                } else if (usesSubjectIdIdentifier && isSubjectIdDefined && isDisplayNameDefined && isEmailDefined) {
                    user = OidcAuthenticationContext.createUser(subject_id, display_name, email);
                } else {
                    return null;
                }

                String role = attributes.get("role");
                if (role != null && role.contains(config.getAdminRole())) {
                    user.setAdmin(true);
                } else {
                    user.setAdmin(false);
                }
            }
        } catch (Exception e) {
            logger.error("Error while creating a user : {}", e.getMessage());
        }
        return user;
    }

}
