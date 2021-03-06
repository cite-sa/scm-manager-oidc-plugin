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

import gr.cite.scm.plugin.oidc.model.OidcAuthConfigModel;
import org.slf4j.LoggerFactory;

import javax.xml.bind.annotation.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * Plugin configuration class
 */
@XmlRootElement(name = "oidc-auth-config")
@XmlAccessorType(XmlAccessType.FIELD)
public class OidcAuthConfig {

    public static class AuthenticationFlow {
        public static final String RESOURCE_OWNER = "Resource Owner Grant Flow";
        public static final String IDENTIFICATION_TOKEN = "Client Identification Token Flow";
    }

    public static class UserIdentifier {
        public static final String SUBJECT_ID = "SubjectId";
        public static final String USERNAME = "Username";
        public static final String EMAIL = "Email";
    }

    @XmlElement(name = "provider-url")
    private String providerUrl;

    @XmlElement(name = "user-identifier")
    private String userIdentifier;

    @XmlElement(name = "admin-role")
    private String adminRole;

    @XmlElement(name = "client-id")
    private String clientId;

    @XmlElement(name = "client-secret")
    private String clientSecret;

    @XmlElement(name = "authentication-flow")
    private String authenticationFlow;

    @XmlElement(name = "enabled")
    private Boolean enabled;

    @XmlTransient
    private Boolean initialized = false;

    /**
     * Sets the initial values from the initialDefaultConfiguration.json file
     */
    public OidcAuthConfig init() {
        if (!initialized) {
            try {
                InputStream jsonStream = OidcAuthConfig.class.getResourceAsStream("/initialDefaultConfiguration.json");
                String jsonString = OidcAuthUtils.convertStreamToString(jsonStream);
                OidcAuthConfigModel model = OidcAuthUtils.parseJSON(jsonString, OidcAuthConfigModel.class);
                if (this.enabled == null) this.enabled = model.getEnabled();
                if (this.clientId == null) this.clientId = model.getClientId();
                if (this.clientSecret == null) this.clientSecret = model.getClientSecret();
                if (this.providerUrl == null) this.providerUrl = model.getProviderUrl();
                if (this.adminRole == null) this.adminRole = model.getAdminRole();
                if (this.userIdentifier == null) this.userIdentifier = model.getUserIdentifier();
                if (this.authenticationFlow == null) this.authenticationFlow = model.getAuthenticationFlow();
                this.initialized = true;
            } catch (IOException | NullPointerException e) {
                LoggerFactory.getLogger(OidcAuthConfig.class).error("Error while trying to load default configuration : {}", e.getMessage());
            }
        }
        return this;
    }

    public String getProviderUrl() {
        return providerUrl;
    }

    public void setProviderUrl(String providerUrl) {
        this.providerUrl = providerUrl;
    }

    public String getUserIdentifier() {
        return userIdentifier;
    }

    public void setUserIdentifier(String userIdentifier) {
        this.userIdentifier = userIdentifier;
    }

    public String getAdminRole() {
        return adminRole;
    }

    public void setAdminRole(String adminRole) {
        this.adminRole = adminRole;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getAuthenticationFlow() {
        return authenticationFlow;
    }

    public void setAuthenticationFlow(String authenticationFlow) {
        this.authenticationFlow = authenticationFlow;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    @Override
    public String toString() {
        return "OidcAuthConfig{" +
                "providerUrl='" + providerUrl + '\'' +
                ", userIdentifier='" + userIdentifier + '\'' +
                ", adminRole='" + adminRole + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                ", authenticationFlow='" + authenticationFlow + '\'' +
                ", enabled=" + enabled +
                ", initialized=" + initialized +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        OidcAuthConfig that = (OidcAuthConfig) o;
        return Objects.equals(providerUrl, that.providerUrl) &&
                Objects.equals(userIdentifier, that.userIdentifier) &&
                Objects.equals(adminRole, that.adminRole) &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(clientSecret, that.clientSecret) &&
                Objects.equals(authenticationFlow, that.authenticationFlow);
    }

    @Override
    public int hashCode() {
        return Objects.hash(providerUrl, userIdentifier, adminRole, clientId, clientSecret, authenticationFlow);
    }
}

