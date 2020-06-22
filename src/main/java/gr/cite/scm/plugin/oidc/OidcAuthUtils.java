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

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.config.ScmConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * General Helper class
 */
public class OidcAuthUtils {

    public static Logger logger = LoggerFactory.getLogger(OidcAuthUtils.class);

    /**
     * Outputs an InputStream to a String
     *
     * @param stream
     * @return
     */
    static String convertStreamToString(java.io.InputStream stream) {
        if (stream == null) {
            return null;
        }
        java.util.Scanner s = new java.util.Scanner(stream).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    /**
     * Determines if the request originated from a browser.
     *
     * @param request
     * @return
     */
    public static boolean isBrowser(final HttpServletRequest request) {
        final String userAgent = request.getHeader("User-Agent");
        if (userAgent != null) {
            return userAgent.startsWith("Mozilla");
        }
        return false;
    }

    /**
     * Returns a mapped object parsed from a json string.
     *
     * @param json
     * @return
     */
    public static <T> T parseJSON(String json, Class<T> clazz) throws IOException {
        logger.debug("JSON parsing started...");
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(json, clazz);
    }

    /**
     * Checks if a JWT token is valid and has the right signature.
     *
     * @param dec_jwt
     * @param provider_url
     * @return
     */
    public static boolean verifyJWT(DecodedJWT dec_jwt, String provider_url) {
        try {
            logger.debug("JWT Signature verification started...");
            JwkProvider provider = new JwkProviderBuilder(new URL(provider_url)).build();
            logger.debug("Loaded Key Provider: key_id -> *************");
            Jwk jwk = provider.get(dec_jwt.getKeyId());
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            Verification verifier = JWT.require(algorithm);
            verifier.build().verify(dec_jwt);
            logger.info("JWT Signature is valid.");
            return true;
        } catch (IllegalArgumentException | JWTVerificationException | MalformedURLException | JwkException e) {
            logger.error("JWT Signature verification failed : " + e.getMessage());
            return false;
        }
    }

    /**
     * Decrypts a given token string.
     *
     * @param token
     * @return
     */
    public static DecodedJWT decodeJWT(String token) {
        DecodedJWT jwt = null;
        try {
            logger.debug("Token decoding started...");
            jwt = JWT.decode(token);
        } catch (JWTVerificationException e) {
            logger.error("Token decode Failed : " + e.getMessage());
        }
        return jwt;
    }

    /**
     * Sends a token request to the provider endpoint and returns the result.
     *
     * @param providerConfig
     * @param authConfig
     * @param scmConfig
     * @param code
     * @return
     * @throws IOException
     */
    public static String sendTokenRequest(OidcProviderConfig providerConfig, OidcAuthConfig authConfig, ScmConfiguration scmConfig, String code) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(providerConfig.getTokenEndpoint());
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("client_id", authConfig.getClientId()));
        params.add(new BasicNameValuePair("client_secret", authConfig.getClientSecret()));
        params.add(new BasicNameValuePair("redirect_uri", scmConfig.getBaseUrl()));
        params.add(new BasicNameValuePair("code", code));
        post.setEntity(new UrlEncodedFormEntity(params));
        logger.debug("Prepared access token request. Sending...");
        String resStr = EntityUtils.toString(httpClient.execute(post).getEntity());
        post.releaseConnection();
        httpClient.close();
        return resStr;
    }

    /**
     * Sends a token request to the provider endpoint using password credentials and returns the result.
     *
     * @param providerConfig
     * @param authConfig
     * @param username
     * @param password
     * @return
     * @throws IOException
     */
    public static String sendPasswordTokenRequest(OidcProviderConfig providerConfig, OidcAuthConfig authConfig, String username, String password) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(providerConfig.getTokenEndpoint());
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "password"));
        params.add(new BasicNameValuePair("client_id", authConfig.getClientId()));
        params.add(new BasicNameValuePair("client_secret", authConfig.getClientSecret()));
        params.add(new BasicNameValuePair("username", username));
        params.add(new BasicNameValuePair("password", password));
        post.setEntity(new UrlEncodedFormEntity(params));
        logger.debug("Prepared password access token request. Sending...");
        String resStr = EntityUtils.toString(httpClient.execute(post).getEntity());
        post.releaseConnection();
        httpClient.close();
        return resStr;
    }

    /**
     * Sends a token request to the provider endpoint using a refresh_token and returns the result.
     *
     * @param providerConfig
     * @param authConfig
     * @param refresh_token
     * @return
     * @throws IOException
     */
    public static String sendRefreshTokenRequest(OidcProviderConfig providerConfig, OidcAuthConfig authConfig, String refresh_token) throws IOException {
        CloseableHttpClient httpClient = HttpClients.createDefault();
        HttpPost post = new HttpPost(providerConfig.getTokenEndpoint());
        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "refresh_token"));
        params.add(new BasicNameValuePair("client_id", authConfig.getClientId()));
        params.add(new BasicNameValuePair("client_secret", authConfig.getClientSecret()));
        params.add(new BasicNameValuePair("refresh_token", refresh_token));
        post.setEntity(new UrlEncodedFormEntity(params));
        logger.debug("Prepared refresh token request. Sending...");
        String resStr = EntityUtils.toString(httpClient.execute(post).getEntity());
        post.releaseConnection();
        httpClient.close();
        return resStr;
    }

    /**
     * Prepares a map with user attributes from the provider token
     *
     * @param authConfig
     * @param jwt
     * @return
     */
    public static Map<String, String> getUserAttributesFromToken(OidcAuthConfig authConfig, DecodedJWT jwt) {
        logger.debug("Token Decoded. Extracting claims...");
        for (String key : jwt.getClaims().keySet()) {
            logger.trace(key + " -> " + jwt.getClaims().get(key).asString());
        }
        Map<String, String> user_attributes = new HashMap<>();
        user_attributes.put("email", jwt.getClaim("email").asString());
        user_attributes.put("username", jwt.getClaim("preferred_username").asString());
        user_attributes.put("display_name", jwt.getClaim("name").asString());
        user_attributes.put("sub", jwt.getClaim("sub").asString());
        String rolesJson;
        try {
            rolesJson = jwt.getClaim("resource_access").as(JsonNode.class).path(authConfig.getClientId()).path("roles").toString();
            logger.debug("User role string: {}", rolesJson);
            if (rolesJson.length() > 0) {
                user_attributes.put("role", rolesJson);
            }
        } catch (NullPointerException ignored) {
        }
        return user_attributes;
    }

    public static class Security {

        public static String generateSecureRandom(int length) {
            SecureRandom sr = new SecureRandom();
            byte[] bytes = new byte[length];
            sr.nextBytes(bytes);
            return DatatypeConverter.printHexBinary(bytes).toLowerCase();
        }

    }

}
