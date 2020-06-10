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

import com.fasterxml.jackson.core.JsonProcessingException;
import gr.cite.scm.plugin.oidc.browser.OidcAuthenticationResource;
import gr.cite.scm.plugin.oidc.browser.OidcLoginHandler;
import gr.cite.scm.plugin.oidc.server.OidcTestServerEndpointResponseBuilder;
import gr.cite.scm.plugin.oidc.token.OidcTestSubject;
import gr.cite.scm.plugin.oidc.token.OidcTestToken;
import gr.cite.scm.plugin.oidc.token.OidcTestTokenBuilder;
import gr.cite.scm.plugin.oidc.utils.OidcAuthService;
import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockserver.client.MockServerClient;
import org.mockserver.junit.MockServerRule;
import org.mockserver.model.MediaType;
import sonia.scm.config.ScmConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;
import java.io.IOException;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

public class OidcAuthenticationFilterTest {

    @Mock
    private OidcAuthConfig authConfig;
    @Mock
    private OidcContext context;
    @Mock
    private OidcProviderConfig oidcProviderConfig;
    @Mock
    private OidcLoginHandler oidcLoginHandler;
    @Mock
    private ScmConfiguration scmConfig;
    @InjectMocks
    private OidcAuthService authService;

    @Rule
    public MockServerRule mockServerRule = new MockServerRule(this);

    private MockServerClient mockServerClient;

    private OidcTestToken testToken = OidcTestTokenBuilder.build(new OidcTestSubject("admin@gmail.com", "admin user", "adminuser", true));

    @Before
    public void init() throws IOException {
        MockitoAnnotations.initMocks(this);

        when(scmConfig.getBaseUrl()).thenReturn("/");

        when(authConfig.getEnabled()).thenReturn(true);
        when(authConfig.getClientId()).thenReturn(OidcAuthUtilsTest.clientId);
        when(authConfig.getClientSecret()).thenReturn(OidcAuthUtilsTest.clientSecret);
        when(authConfig.getProviderUrl()).thenReturn("http://localhost:" + mockServerRule.getPort() + "/well-known");
        when(authConfig.getUserIdentifier()).thenReturn("Email");

        when(oidcProviderConfig.getTokenEndpoint()).thenReturn("http://localhost:" + mockServerRule.getPort() + "/token");
        when(oidcProviderConfig.getJwksUri()).thenReturn("http://localhost:" + mockServerRule.getPort() + "/certs");
    }

    @Test
    public void shouldTestMockServerStartedAndConfigured() {
        assertTrue("Failure - Could not start Mock Server", mockServerClient.hasStarted());
    }

    @Test
    public void shouldValidateUserFromMockServer() throws IOException {
        addExpectations();
        String code = "4f8ec13a-56fd-4752-a0f4-37d51b3c2b07.00b72168-553c-4d38-ac4a-b1eda767edcf.ff9fd9da-987d-457d-8c0a-fafca34123ac";

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);

        when(request.getContextPath()).thenReturn("/");
        when(request.getRequestURI()).thenReturn("/");
        when(context.get()).thenReturn(authConfig);

        OidcAuthenticationResource authenticationResource = new OidcAuthenticationResource(scmConfig, context, oidcProviderConfig, authService, oidcLoginHandler);

        assertTrue("Response not successful : OpenID Authentication process ended unexpectedly...", authenticationResource.login(request, response, code).getStatus() != HttpStatus.SC_UNAUTHORIZED);
    }

    private void addExpectations() throws JsonProcessingException {
        setupTokenEndpoint();
        setupCertificatesEndpoint();
    }

    private void setupTokenEndpoint() throws JsonProcessingException {
        mockServerClient.when(
                request()
                        .withPath("/token").withMethod(HttpMethod.POST)
        ).respond(
                response()
                        .withStatusCode(HttpStatus.SC_OK)
                        .withBody(OidcTestServerEndpointResponseBuilder.buildTokensEndpointResponse(testToken), MediaType.APPLICATION_JSON)
        );
    }

    private void setupCertificatesEndpoint() throws JsonProcessingException {
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
