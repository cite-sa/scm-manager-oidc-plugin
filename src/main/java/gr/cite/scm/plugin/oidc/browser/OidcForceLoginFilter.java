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

import com.google.common.base.Strings;
import gr.cite.scm.plugin.oidc.OidcAuthConfig;
import gr.cite.scm.plugin.oidc.OidcContext;
import gr.cite.scm.plugin.oidc.OidcProviderConfig;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.Priority;
import sonia.scm.config.ScmConfiguration;
import sonia.scm.filter.Filters;
import sonia.scm.filter.WebElement;
import sonia.scm.security.Authentications;
import sonia.scm.util.HttpUtil;
import sonia.scm.web.UserAgentParser;
import sonia.scm.web.filter.HttpFilter;

import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

@WebElement("/*")
@Priority(Filters.PRIORITY_POST_AUTHENTICATION)
public class OidcForceLoginFilter extends HttpFilter {

    Logger logger = LoggerFactory.getLogger(OidcForceLoginFilter.class);

    private final OidcContext context;
    private final OidcProviderConfig providerConfig;
    private final ScmConfiguration scmConfiguration;
    private final UserAgentParser userAgentParser;

    @Inject
    public OidcForceLoginFilter(OidcContext context, OidcProviderConfig providerConfig, ScmConfiguration scmConfiguration, UserAgentParser userAgentParser) {
        this.context = context;
        this.providerConfig = providerConfig.init();
        this.scmConfiguration = scmConfiguration;
        this.userAgentParser = userAgentParser;

    }

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        logger.debug("Login filter reached.");
        if (requestIsAllowed(request)) {
            chain.doFilter(request, response);
        } else if (isWebInterfaceRequest(request)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        } else {
            redirectToOidcProviderLogin(response);
        }
    }

    /**
     * Returns true if the request must continue down the chain.
     *
     * @param request
     * @return
     */
    private boolean requestIsAllowed(HttpServletRequest request) {
        Subject subject = SecurityUtils.getSubject();
        return subject.isAuthenticated() && !Authentications.isAuthenticatedSubjectAnonymous()
                || isOidcAuthenticationDisabled()
                || isOidcCallback(request)
                || isAnonymousProtocolRequest(request);
    }

    /**
     * Returns true if the request is coming from anonymous sources.
     *
     * @param request
     * @return
     */
    private boolean isAnonymousProtocolRequest(HttpServletRequest request) {
        return !HttpUtil.isWUIRequest(request)
                && Authentications.isAuthenticatedSubjectAnonymous()
                && scmConfiguration.isAnonymousAccessEnabled()
                && !userAgentParser.parse(request).isBrowser();
    }

    /**
     * Returns true if the request is allowed from the server.
     *
     * @param request
     * @return
     */
    private boolean isWebInterfaceRequest(HttpServletRequest request) {
        return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
    }

    /**
     * Returns true if the current scm configuration allows anonymous access.
     *
     * @return
     */
    private boolean isOidcAuthenticationDisabled() {
        return !context.get().getEnabled();
    }

    /**
     * Returns true if the request is coming from the Open Id Connect plugin.
     *
     * @param request
     * @return
     */
    private boolean isOidcCallback(HttpServletRequest request) {
        return request.getRequestURI().startsWith(request.getContextPath() + "/api/v2/oidc/")
                && (isOidcLoginRequest(request) || isOidcLogoutRequest(request));
    }

    /**
     * Returns true if the given request is the login request.
     *
     * @param request
     * @return
     */
    private boolean isOidcLoginRequest(HttpServletRequest request) {
        return "GET".equals(request.getMethod()) && !Strings.isNullOrEmpty(request.getParameter("code"));
    }

    /**
     * Returns true if the given request is the logout request.
     *
     * @param request
     * @return
     */
    private boolean isOidcLogoutRequest(HttpServletRequest request) {
        return "GET".equals(request.getMethod()) && request.getRequestURI().endsWith("logout");
    }

    /**
     * Redirects the user to Open Id Connect provider for authentication.
     *
     * @param response
     * @throws IOException
     */
    private void redirectToOidcProviderLogin(HttpServletResponse response) throws IOException {
        response.sendRedirect(getProviderCodeRequestString());
    }

    /**
     * Generates the code request url
     *
     * @return
     */
    private String getProviderCodeRequestString() {
        OidcAuthConfig authConfig = context.get();
        return providerConfig.getAuthorizationEndpoint() + "?" +
                "client_id=" + authConfig.getClientId() +
                "&redirect_uri=" + scmConfiguration.getBaseUrl() + "/api/" + OidcAuthenticationResource.PATH +
                "&scope=openid profile email phone address roles" +
                "&response_type=code" +
                "&state=" + UUID.randomUUID().toString().replace("-", "");
    }

}
