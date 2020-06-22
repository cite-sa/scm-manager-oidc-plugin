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
import gr.cite.scm.plugin.oidc.OidcAuthUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;

public class OidcClientTokenIssuer {

    private static Logger logger = LoggerFactory.getLogger(OidcClientTokenIssuer.class);

    private OidcClientTokensStore clientTokensStore;

    private static final long DEFAULT_LIFETIME = 0;

    @Inject
    public OidcClientTokenIssuer(OidcClientTokensStore clientTokensStore) {
        this.clientTokensStore = clientTokensStore;
    }

    /**
     * Gets the tokens configuration for the given user.
     *
     * @param subject The user identifier
     * @return The configuration (null if not set)
     */
    public OidcClientTokensStore.ConfigRecord getConfiguration(String subject) {
        logger.debug("Fetching identification token configuration for user -> {}", subject);
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        OidcClientTokensStore.Config config = tokens.getConfig();
        List<OidcClientTokensStore.ConfigRecord> configRecords = config.getConfigRecordList();
        for (OidcClientTokensStore.ConfigRecord configRecord : configRecords) {
            if (configRecord.getSubject().equals(subject)) {
                if (configRecord.getLifetime() < 0) {
                    configRecord.setLifetime(0);
                }
                return configRecord;
            }
        }
        logger.debug("No identification token configuration found... Generating default configuration for user -> {}", subject);
        for (OidcClientTokensStore.Token token : getUserTokens(subject)) {
            invalidate(token.getId());
        }
        OidcClientTokensStore.ConfigRecord configRecord = new OidcClientTokensStore.ConfigRecord(DEFAULT_LIFETIME, subject);
        configRecords.add(configRecord);
        config.setConfigRecordList(configRecords);
        tokens.setConfig(config);
        clientTokensStore.set(tokens);
        return configRecord;
    }

    /**
     * Updates the user's token configuration to store.
     *
     * @param lifetime The time in hours
     * @param subject  The user identifier
     */
    public void saveConfiguration(long lifetime, String subject) {
        logger.debug("Updating identification token configuration for user -> {}", subject);
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        OidcClientTokensStore.Config config = tokens.getConfig();
        List<OidcClientTokensStore.ConfigRecord> configRecords = config.getConfigRecordList();
        OidcClientTokensStore.ConfigRecord configRecord = new OidcClientTokensStore.ConfigRecord(lifetime, subject);
        for (int i = 0; i < configRecords.size(); i++) {
            if (configRecords.get(i).getSubject().equals(subject)) {
                configRecord.setSalt(configRecords.get(i).getSalt());
                configRecords.set(i, configRecord);
                break;
            }
        }
        config.setConfigRecordList(configRecords);
        tokens.setConfig(config);
        clientTokensStore.set(tokens);
    }

    /**
     *Removes all user token configurations
     */
    public void clearAllConfigurations() {
        logger.debug("Removing identification token configuration for all users");
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        OidcClientTokensStore.Config config = tokens.getConfig();
        config.setConfigRecordList(new ArrayList<>());
        tokens.setConfig(config);
        clientTokensStore.set(tokens);
    }

    /**
     * Gets the provider tokens for the given user.
     *
     * @param subject The user identifier
     * @return The provider tokens (null if not set)
     */
    public OidcClientTokensStore.ProviderToken getProviderTokens(String subject) {
        logger.debug("Fetching the provider tokens for user -> {}", subject);
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.ProviderToken> providerTokens = tokens.getProviderTokenList();
        for (OidcClientTokensStore.ProviderToken providerToken : providerTokens) {
            if (providerToken.getSubject().equals(subject)) {
                return providerToken;
            }
        }
        return null;
    }

    /**
     * Adds the user's provider tokens to store for future validation.
     *
     * @param access_token  The access token
     * @param refresh_token The refresh token
     * @param subject       The user identifier
     */
    public void saveProviderTokens(String access_token, String refresh_token, String subject) {
        logger.debug("Saving provider tokens for user {}", subject);
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.ProviderToken> providerTokens = tokens.getProviderTokenList();
        OidcClientTokensStore.ProviderToken providerToken = new OidcClientTokensStore.ProviderToken(OidcAuthUtils.decodeJWT(access_token).getExpiresAt().getTime(), refresh_token, subject);
        if (!providerTokens.contains(providerToken)) {
            providerTokens.add(providerToken);
        } else {
            for (int i = 0; i < providerTokens.size(); i++) {
                if (providerTokens.get(i).getSubject().equals(subject)) {
                    providerTokens.set(i, providerToken);
                    break;
                }
            }
        }
        tokens.setProviderTokenList(providerTokens);
        clientTokensStore.set(tokens);
    }

    /**
     * Removes the user's provider tokens from the store.
     *
     * @param subject The user identifier
     */
    public void removeProviderTokens(String subject) {
        logger.debug("Removing provider tokens for user {}", subject);
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.ProviderToken> providerTokens = tokens.getProviderTokenList();
        int index = -1;
        for (int i = 0; i < providerTokens.size(); i++) {
            if (providerTokens.get(i).getSubject().equals(subject)) {
                index = i;
                break;
            }
        }
        if (index != -1) providerTokens.remove(index);
        tokens.setProviderTokenList(providerTokens);
        clientTokensStore.set(tokens);
    }

    /**
     * Removes all the provider tokens from the store.
     */
    public void removeAllProviderTokens() {
        logger.debug("Removing all provider tokens from the store");
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        tokens.setProviderTokenList(new ArrayList<>());
        clientTokensStore.set(tokens);
    }

    /**
     * Generates a new client identification token for the given subject (user) with specific validity duration.
     *
     * @param subject  The user identifier
     * @param validFor The time of validity in hours
     * @return The body (payload) of the token
     */
    public OidcClientTokensStore.Token issue(String subject, long validFor) {
        logger.debug("Started issuing new client identification token...");
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.Token> tokenList = tokens.getTokenList();
        String body = generateTokenString();
        logger.debug("Token body generated -> ***********");
        OidcClientTokensStore.Token token = new OidcClientTokensStore.Token(hash(subject, body), subject, System.currentTimeMillis(), validFor);
        tokenList.add(token);
        tokens.setTokenList(tokenList);
        clientTokensStore.set(tokens);
        token.setRawBody(body);
        logger.debug("Client identification token issued.");
        return token;
    }

    /**
     * Generates a new client identification token for the given subject (user) using default or user settings based validity duration.
     *
     * @param subject The user identifier
     * @return The body (payload) of the token
     */
    public OidcClientTokensStore.Token issue(String subject) {
        OidcClientTokensStore.ConfigRecord config = getConfiguration(subject);
        if (config != null && config.getLifetime() >= 0) {
            return issue(subject, config.getLifetime());
        }
        return issue(subject, DEFAULT_LIFETIME);
    }

    /**
     * Removes the identification token from the store.
     *
     * @param id The id of the token
     */
    public void invalidate(String id) {
        logger.debug("Started client identification token invalidation...");
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.Token> tokenList = tokens.getTokenList();
        int index = -1;
        for (int i = 0; i < tokenList.size(); i++) {
            OidcClientTokensStore.Token token = tokenList.get(i);
            if (token.getId().equals(id)) {
                index = i;
                break;
            }
        }
        if (index != -1) {
            tokenList.remove(index);
        }
        tokens.setTokenList(tokenList);
        clientTokensStore.set(tokens);
        logger.debug("Client identification token {} got invalidated.", id);
    }

    /**
     * Removes all the expired client identification tokens from the store.
     */
    public void clearInvalidTokens() {
        logger.debug("Removing expired identification tokens...");
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.Token> tokenList = tokens.getTokenList();
        List<OidcClientTokensStore.Token> toRemove = new ArrayList<>();
        for (OidcClientTokensStore.Token token : tokenList) {
            if (!token.isValid()) {
                toRemove.add(token);
            }
        }
        tokenList.removeAll(toRemove);
        tokens.setTokenList(tokenList);
        clientTokensStore.set(tokens);
        logger.debug("Expired identification tokens got removed.");
    }

    /**
     * Removes all the client identification tokens from the store.
     */
    public void clearAllTokens() {
        logger.debug("Removing all identification tokens...");
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        tokens.setTokenList(new ArrayList<>());
        clientTokensStore.set(tokens);
        logger.debug("All identification tokens got removed.");
    }

    /**
     * Gets the client identification tokens for the given user.
     *
     * @param user The user identifier
     * @return The user token list
     */
    public List<OidcClientTokensStore.Token> getUserTokens(String user) {
        clearInvalidTokens();
        logger.debug("Fetching identification tokens for user -> {}", user);
        List<OidcClientTokensStore.Token> userTokens = new ArrayList<>();
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.Token> tokenList = tokens.getTokenList();
        for (OidcClientTokensStore.Token token : tokenList) {
            if (token.getSubject().equals(user)) {
                userTokens.add(token);
            }
        }
        return userTokens;
    }

    /**
     * Returns the user that the given identification token corresponds to
     *
     * @param password The raw token given by the client
     * @return The user identifier
     */
    public String getUserByToken(String password) {
        clearInvalidTokens();
        OidcClientTokensStore.Tokens tokens = clientTokensStore.get();
        List<OidcClientTokensStore.Token> tokenList = tokens.getTokenList();
        for (OidcClientTokensStore.Token token : tokenList) {
            if (checkHash(token.getSubject(), token.getBody(), password)) {
                return token.getSubject();
            }
        }
        return null;
    }

    /**
     * Clears all the information from the tokens store
     */
    public void resetTokenStore() {
        clearAllTokens();
        removeAllProviderTokens();
        clearAllConfigurations();
    }

    /**
     * Generates a random string for the token body
     *
     * @return The string
     */
    public static String generateTokenString() {
        return OidcAuthUtils.Security.generateSecureRandom(16);
    }

    /**
     * Generates a secure hash from the input string using the SHA256 algorithm and a configured salt.
     *
     * @param subject The user identifier
     * @param input   The token to get hashed
     * @return The hashed token
     */
    public String hash(String subject, String input) {
        logger.debug("Generating secure hash from token...");
        OidcClientTokensStore.ConfigRecord config = getConfiguration(subject);
        KeySpec spec = new PBEKeySpec(input.toCharArray(), config.getSalt().getBytes(), 65536, 256);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return DatatypeConverter.printHexBinary(factory.generateSecret(spec).getEncoded()).toLowerCase();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            logger.error("Exception while generating secure hash for a token");
        }
        return null;
    }

    /**
     * Checks if the given password gives the stored user hash.
     *
     * @param subject  The user identifier
     * @param hash     The stored hash
     * @param password The raw password
     * @return true or false based on the check
     */
    public boolean checkHash(String subject, String hash, String password) {
        return hash.equals(hash(subject, password));
    }

}
