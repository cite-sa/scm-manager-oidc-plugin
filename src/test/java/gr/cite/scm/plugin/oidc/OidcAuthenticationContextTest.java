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

import gr.cite.scm.plugin.oidc.helpers.jwt.OidcTestSubject;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import sonia.scm.user.User;

import javax.servlet.http.HttpServletRequest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class OidcAuthenticationContextTest {

    @Mock
    OidcAuthConfig authConfig;
    @Mock
    HttpServletRequest request;

    private OidcTestSubject demoUser = new OidcTestSubject("demo@gmail.com", "demo user", "demouser", false);
    private OidcTestSubject demoAdminUser = new OidcTestSubject("admin@gmail.com", "demo admin", "demoadmin", true);

    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void shouldReturnUser() {
        when(authConfig.getUserIdentifier()).thenReturn(OidcAuthConfig.UserIdentifier.SUBJECT_ID);

        when(request.getAttribute("user_attributes")).thenReturn(generateUserAttributesMap(false));

        User user = OidcAuthenticationContext.createOidcUser(authConfig, request);

        assertNotNull(user);
        assertEquals(demoUser.getName(), user.getDisplayName());
        assertEquals(demoUser.getSub(), user.getName());
        assertEquals(demoUser.getEmail(), user.getMail());
        assertFalse("Failure - User should not be admin", user.isAdmin());
    }

    @Test
    public void shouldReturnAdminUser() {
        when(authConfig.getUserIdentifier()).thenReturn(OidcAuthConfig.UserIdentifier.EMAIL);
        when(authConfig.getAdminRole()).thenReturn("admin");

        when(request.getAttribute("user_attributes")).thenReturn(generateUserAttributesMap(true));

        User user = OidcAuthenticationContext.createOidcUser(authConfig, request);

        assertNotNull(user);
        assertEquals(demoAdminUser.getName(), user.getDisplayName());
        assertEquals(demoAdminUser.getEmail(), user.getName());
        assertEquals(demoAdminUser.getEmail(), user.getMail());
        assertTrue("Failure - User should be admin", user.isAdmin());
    }

    private Map<String, String> generateUserAttributesMap(boolean admin){
        Map<String, String> attributes = new HashMap<>();
        if(admin){
            attributes.put("username", demoAdminUser.getPreferredUsername());
            attributes.put("display_name", demoAdminUser.getName());
            attributes.put("email", demoAdminUser.getEmail());
            attributes.put("sub", demoAdminUser.getSub());
            attributes.put("role", "[\"admin\"]");
        }else{
            attributes.put("username", demoUser.getPreferredUsername());
            attributes.put("display_name", demoUser.getName());
            attributes.put("email", demoUser.getEmail());
            attributes.put("sub", demoUser.getSub());
        }
        return attributes;
    }

}
