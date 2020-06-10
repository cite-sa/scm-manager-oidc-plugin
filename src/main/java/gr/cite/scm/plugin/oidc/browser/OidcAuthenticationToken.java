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

import gr.cite.scm.plugin.oidc.OidcUserContext;
import org.apache.shiro.authc.AuthenticationToken;

import java.util.Map;

public class OidcAuthenticationToken implements AuthenticationToken {

    private final String accessToken;

    private OidcUserContext userContext;
    private Map<String, String> user_attributes;

    private OidcAuthenticationToken(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public Object getPrincipal() {
        return accessToken;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    public static OidcAuthenticationToken get(String accessToken) {
        return new OidcAuthenticationToken(accessToken);
    }

    /**
     * Sets the UserContext instance.
     *
     * @param userContext
     * @return
     */
    public OidcAuthenticationToken withUserContext(OidcUserContext userContext) {
        this.userContext = userContext;
        return this;
    }

    /**
     * Sets the user attributes map.
     *
     * @param user_attributes
     * @return
     */
    public OidcAuthenticationToken withUserAttributes(Map<String, String> user_attributes) {
        this.user_attributes = user_attributes;
        return this;
    }

    public OidcUserContext getUserContext() {
        return userContext;
    }

    public Map<String, String> getUserAttributes() {
        return this.user_attributes;
    }

}
