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
package gr.cite.scm.plugin.oidc.token;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import gr.cite.scm.plugin.oidc.OidcAuthUtils;
import sonia.scm.store.Store;
import sonia.scm.store.StoreFactory;

import javax.xml.bind.annotation.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Singleton
public class OidcClientTokensStore {

    private static final String STORE_NAME = "tokens";
    private Store<Tokens> store;
    private Tokens tokens;

    @Inject
    public OidcClientTokensStore(StoreFactory storeFactory) {
        store = storeFactory.getStore(Tokens.class, STORE_NAME);
        tokens = store.get();
        if (tokens == null) {
            tokens = new Tokens();
        }
    }

    public Tokens get() {
        return tokens;
    }

    public void set(Tokens tokens) {
        this.tokens = tokens;
        store.set(tokens);
    }

    @XmlRootElement(name = "configuration")
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Config {

        @XmlElement(name = "configuration-record")
        private List<ConfigRecord> configRecordList = new ArrayList<>();

        public Config() {
        }

        public List<ConfigRecord> getConfigRecordList() {
            return configRecordList;
        }

        public void setConfigRecordList(List<ConfigRecord> configRecordList) {
            this.configRecordList = configRecordList;
        }
    }

    @XmlRootElement(name = "configuration-record")
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class ConfigRecord {

        @XmlElement(name = "salt")
        private String salt;

        /**
         * In seconds
         */
        @XmlElement(name = "lifetime")
        private long lifetime;

        /**
         * User
         */
        @XmlElement(name = "subject")
        private String subject;

        public ConfigRecord() {
        }

        public ConfigRecord(long lifetime, String subject) {
            this.salt = OidcAuthUtils.Security.generateSecureRandom(32);
            this.lifetime = lifetime;
            this.subject = subject;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }

        public long getLifetime() {
            return lifetime;
        }

        public void setLifetime(long lifetime) {
            this.lifetime = lifetime;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ConfigRecord that = (ConfigRecord) o;
            return Objects.equals(subject, that.subject);
        }

        @Override
        public int hashCode() {
            return Objects.hash(subject);
        }
    }

    @XmlRootElement(name = "tokens")
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Tokens {

        /**
         * Contains the token configuration
         */
        @XmlElement(name = "configuration")
        private Config config = new Config();

        /**
         * Contains the provider tokens
         */
        @XmlElementWrapper(name = "provider-tokens")
        @XmlElement(name = "provider-token")
        private List<ProviderToken> providerTokenList = new ArrayList<>();

        /**
         * Contains the client identification tokens
         */
        @XmlElementWrapper(name = "identification-tokens")
        @XmlElement(name = "identification-token")
        private List<Token> tokenList = new ArrayList<>();

        public Config getConfig() {
            return config;
        }

        public void setConfig(Config config) {
            this.config = config;
        }

        public List<ProviderToken> getProviderTokenList() {
            return providerTokenList;
        }

        public void setProviderTokenList(List<ProviderToken> providerTokenList) {
            this.providerTokenList = providerTokenList;
        }

        public List<Token> getTokenList() {
            return tokenList;
        }

        public void setTokenList(List<Token> tokenList) {
            this.tokenList = tokenList;
        }
    }

    @XmlRootElement(name = "provider-token")
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class ProviderToken {

        @XmlElement(name = "access-token-expires-at")
        private long accessTokenExpiresAt;

        @XmlElement(name = "refresh-token")
        private String refreshToken;

        /**
         * User
         */
        @XmlElement(name = "subject")
        private String subject;

        public ProviderToken() {
        }

        public ProviderToken(long accessTokenExpiresAt, String refreshToken, String subject) {
            this.accessTokenExpiresAt = accessTokenExpiresAt;
            this.refreshToken = refreshToken;
            this.subject = subject;
        }

        public long getAccessTokenExpiresAt() {
            return accessTokenExpiresAt;
        }

        public void setAccessTokenExpiresAt(long accessTokenExpiresAt) {
            this.accessTokenExpiresAt = accessTokenExpiresAt;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            ProviderToken that = (ProviderToken) o;
            return Objects.equals(subject, that.subject);
        }

        @Override
        public int hashCode() {
            return Objects.hash(subject);
        }
    }

    @XmlRootElement(name = "identification-token")
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Token {

        @XmlElement(name = "id")
        private String id;

        /**
         * Payload
         */
        @XmlElement(name = "body")
        private String body;

        /**
         * User
         */
        @XmlElement(name = "subject")
        private String subject;

        /**
         * Timestamp in milliseconds
         */
        @XmlElement(name = "issued-at")
        private long issuedAt;

        /**
         * Time in hours
         */
        @XmlElement(name = "valid-for")
        private long validFor;

        /**
         * Timestamp in milliseconds
         */
        @XmlElement(name = "expires-at")
        private long expiresAt;

        @XmlTransient
        private String rawBody;

        public Token() {
        }

        public Token(String body, String subject, long issuedAt, long validFor) {
            this.id = UUID.randomUUID().toString();
            this.body = body;
            this.subject = subject;
            this.issuedAt = issuedAt;
            this.validFor = validFor;
            this.expiresAt = validFor == 0 ? 0 : this.issuedAt + this.validFor * 1000 * 3600;
        }

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getBody() {
            return body;
        }

        public void setBody(String body) {
            this.body = body;
        }

        public String getSubject() {
            return subject;
        }

        public void setSubject(String subject) {
            this.subject = subject;
        }

        public long getIssuedAt() {
            return issuedAt;
        }

        public void setIssuedAt(long issuedAt) {
            this.issuedAt = issuedAt;
        }

        public long getValidFor() {
            return validFor;
        }

        public void setValidFor(long validFor) {
            this.validFor = validFor;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(long expiresAt) {
            this.expiresAt = expiresAt;
        }

        public String getRawBody() {
            return rawBody;
        }

        public void setRawBody(String rawBody) {
            this.rawBody = rawBody;
        }

        public boolean isValid() {
            return getExpiresAt() > System.currentTimeMillis() || getValidFor() == 0;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Token token = (Token) o;
            return Objects.equals(id, token.id);
        }

        @Override
        public int hashCode() {
            return Objects.hash(id);
        }
    }

}
