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

import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import gr.cite.scm.plugin.oidc.helpers.server.OidcTestServerEndpointResponseBuilder;
import gr.cite.scm.plugin.oidc.helpers.jwt.OidcTestSubject;
import gr.cite.scm.plugin.oidc.helpers.jwt.OidcTestToken;
import gr.cite.scm.plugin.oidc.helpers.jwt.OidcTestTokenBuilder;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.MockServerRule;
import org.mockserver.model.MediaType;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.HttpMethod;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class OidcAuthUtilsTest {

    private OidcTestSubject adminTestSubject = new OidcTestSubject("admin@gmail.com", "admin user", "adminuser", true);
    private OidcTestToken adminTestToken = OidcTestTokenBuilder.build(adminTestSubject);
    private OidcTestToken adminExpiredTestToken = OidcTestTokenBuilder.build(adminTestSubject, true);

    private OidcTestSubject simpleTestSubject = new OidcTestSubject("simple@gmail.com", "simple user", "simpleuser", false);
    private OidcTestToken simpleTestToken = OidcTestTokenBuilder.build(simpleTestSubject);

    public static final String clientId = "my-client";
    public static final String adminClaim = "admin";

    @Mock
    private HttpServletRequest httpServletRequest;
    @Mock
    private DecodedJWT decodedJWT;
    @Mock
    private OidcAuthConfig authConfig;

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this);

    private MockServerClient mockServerClient;


    @Before
    public void setup() {
        MockitoAnnotations.initMocks(this);
        when(authConfig.getClientId()).thenReturn(clientId);
    }

    @Test
    public void shouldNotBeFromBrowser() {
        when(httpServletRequest.getHeader("User-Agent")).thenReturn(null).thenReturn("Other Agent");
        assertFalse("failure - should return false", OidcAuthUtils.isBrowser(httpServletRequest));
        assertFalse("failure - should return false", OidcAuthUtils.isBrowser(httpServletRequest));
    }

    @Test
    public void shouldBeFromBrowser() {
        when(httpServletRequest.getHeader("User-Agent")).thenReturn("Mozilla");
        assertTrue("failure - should return true", OidcAuthUtils.isBrowser(httpServletRequest));
    }

    @Test
    public void shouldVerifyNotExpiredJwt() throws JsonProcessingException {
        setupCertificatesEndpoint(adminTestToken);
        assertTrue("failure - should return true", OidcAuthUtils.verifyJWT(OidcAuthUtils.decodeJWT(adminTestToken.getX5c()), getProviderKeyEndpoint()));
    }

    @Test
    public void shouldNotVerifyInvalidJwt() {
        assertFalse("failure - should return false", OidcAuthUtils.verifyJWT(decodedJWT, "http://www.not-existing.com"));
    }

    @Test
    public void shouldNotVerifyExpiredJwt() throws JsonProcessingException {
        setupCertificatesEndpoint(adminExpiredTestToken);
        assertFalse("failure - should return false", OidcAuthUtils.verifyJWT(OidcAuthUtils.decodeJWT(adminExpiredTestToken.getX5c()), getProviderKeyEndpoint()));
    }

    @Test
    public void shouldNotDecodeJwt() {
        assertNull("failure - should return null", OidcAuthUtils.decodeJWT("Not a token"));
    }

    @Test
    public void shouldDecodeJwt() {
        assertNotNull("failure - should return a decoded jwt instance", OidcAuthUtils.decodeJWT(adminTestToken.getX5c()));
    }

    @Test
    public void shouldPopulateAdminAttributes() {
        Map<String, String> attributes = OidcAuthUtils.getUserAttributesFromToken(authConfig, OidcAuthUtils.decodeJWT(adminTestToken.getX5c()));
        assertEquals(adminTestSubject.getSub(), attributes.get("sub"));
        assertEquals(adminTestSubject.getEmail(), attributes.get("email"));
        assertEquals(adminTestSubject.getPreferredUsername(), attributes.get("username"));
        assertEquals(adminTestSubject.getName(), attributes.get("display_name"));
        assertEquals("[\""+OidcAuthUtilsTest.adminClaim+"\"]", attributes.get("role"));
    }

    @Test
    public void shouldPopulateAttributes() {
        Map<String, String> attributes = OidcAuthUtils.getUserAttributesFromToken(authConfig, OidcAuthUtils.decodeJWT(simpleTestToken.getX5c()));
        assertEquals(simpleTestSubject.getSub(), attributes.get("sub"));
        assertEquals(simpleTestSubject.getEmail(), attributes.get("email"));
        assertEquals(simpleTestSubject.getPreferredUsername(), attributes.get("username"));
        assertEquals(simpleTestSubject.getName(), attributes.get("display_name"));
        assertNull(attributes.get("role"));
    }

    private String getProviderKeyEndpoint() {
        return "http://localhost:" + mockServerRule.getPort() + "/certs";
    }

    private void setupCertificatesEndpoint(OidcTestToken testToken) throws JsonProcessingException {
        mockServerClient.when(
                request()
                        .withPath("/certs").withMethod(HttpMethod.GET)
        ).respond(
                response()
                        .withStatusCode(HttpStatus.SC_OK)
                        .withBody(OidcTestServerEndpointResponseBuilder.buildCertificatesEndpointResponse(testToken), MediaType.APPLICATION_JSON)
        );
    }

}
