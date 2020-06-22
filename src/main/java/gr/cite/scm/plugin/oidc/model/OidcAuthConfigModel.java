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
package gr.cite.scm.plugin.oidc.model;

public class OidcAuthConfigModel {

    private String providerUrl, userIdentifier, adminRole, clientId, clientSecret, authenticationFlow;
    private Boolean enabled;

    public void setProviderUrl(String providerUrl) {
        this.providerUrl = providerUrl;
    }

    public void setUserIdentifier(String userIdentifier) {
        this.userIdentifier = userIdentifier;
    }

    public void setAdminRole(String adminRole) {
        this.adminRole = adminRole;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public void setAuthenticationFlow(String authenticationFlow) {
        this.authenticationFlow = authenticationFlow;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public String getProviderUrl() {
        if (providerUrl == null) throw new NullPointerException();
        return providerUrl;
    }

    public String getUserIdentifier() {
        if (userIdentifier == null) throw new NullPointerException();
        return userIdentifier;
    }

    public String getAdminRole() {
        if (adminRole == null) throw new NullPointerException();
        return adminRole;
    }

    public String getClientId() {
        if (clientId == null) throw new NullPointerException();
        return clientId;
    }

    public String getClientSecret() {
        if (clientSecret == null) throw new NullPointerException();
        return clientSecret;
    }

    public String getAuthenticationFlow() {
        return authenticationFlow;
    }

    public Boolean getEnabled() {
        if (enabled == null) throw new NullPointerException();
        return enabled;
    }
}
