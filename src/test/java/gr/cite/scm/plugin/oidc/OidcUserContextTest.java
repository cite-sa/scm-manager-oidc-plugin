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

import gr.cite.scm.plugin.oidc.token.OidcTestSubject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class OidcUserContextTest {

    @Mock
    OidcAuthConfig authConfig;

    private OidcTestSubject demoUser = new OidcTestSubject("demo@gmail.com", "demo user", "demouser", false);
    private OidcTestSubject demoAdminUser = new OidcTestSubject("admin@gmail.com", "demo admin", "demoadmin", true);

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldReturnUser() {
        when(authConfig.getUserIdentifier()).thenReturn("SubjectID");
        OidcUserContext userContext = new OidcUserContext();
        Map<String, String> user_attributes = generateUserAttributesMap(false);
        assertEquals(demoUser.getName(), userContext.createOidcUser(authConfig, user_attributes).getDisplayName());
        assertEquals(demoUser.getSub(), userContext.createOidcUser(authConfig, user_attributes).getName());
        assertEquals(demoUser.getEmail(), userContext.createOidcUser(authConfig, user_attributes).getMail());
        assertFalse("Failure - User should not be admin", userContext.isAdmin());
    }

    @Test
    public void shouldReturnAdminUser() {
        when(authConfig.getUserIdentifier()).thenReturn("Email");
        when(authConfig.getAdminRole()).thenReturn(OidcAuthUtilsTest.adminClaim);
        OidcUserContext userContext = new OidcUserContext();
        Map<String, String> user_attributes = generateUserAttributesMap(true);

        assertEquals(demoAdminUser.getName(), userContext.createOidcUser(authConfig, user_attributes).getDisplayName());
        assertEquals(demoAdminUser.getEmail(), userContext.createOidcUser(authConfig, user_attributes).getName());
        assertEquals(demoAdminUser.getEmail(), userContext.createOidcUser(authConfig, user_attributes).getMail());
        assertTrue("Failure - User should be admin", userContext.isAdmin());
    }

    private Map<String, String> generateUserAttributesMap(boolean admin){
        Map<String, String> attributes = new HashMap<>();
        if(admin){
            attributes.put("username", demoAdminUser.getPreferredUsername());
            attributes.put("display_name", demoAdminUser.getName());
            attributes.put("email", demoAdminUser.getEmail());
            attributes.put("sub", demoAdminUser.getSub());
            attributes.put("role", "[\""+OidcAuthUtilsTest.adminClaim+"\"]");
        }else{
            attributes.put("username", demoUser.getPreferredUsername());
            attributes.put("display_name", demoUser.getName());
            attributes.put("email", demoUser.getEmail());
            attributes.put("sub", demoUser.getSub());
        }
        return attributes;
    }

}
