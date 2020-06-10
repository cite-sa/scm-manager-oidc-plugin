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
package gr.cite.scm.plugin.oidc.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import gr.cite.scm.plugin.oidc.OidcAuthUtilsTest;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class OidcTestTokenBuilder {

    private static String modulus, exponent, keyId = "wipp68B2j3v5SwTNnEwfZ6WLd3AbVtpT2HUKx-_FEVg", x5c;

    public static OidcTestToken build(OidcTestSubject subject) {
        x5c = generateJwt(subject, false);
        return new OidcTestToken(modulus, exponent, keyId, x5c);
    }

    public static OidcTestToken build(OidcTestSubject subject, boolean expired) {
        x5c = generateJwt(subject, expired);
        return new OidcTestToken(modulus, exponent, keyId, x5c);
    }

    private static String generateJwt(OidcTestSubject subject, boolean expired) {
        KeyPairGenerator g;
        try {
            g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KeyPair kp = g.generateKeyPair();
            x5c = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
            modulus = Base64.getEncoder().encodeToString(((RSAPublicKey) kp.getPublic()).getModulus().toByteArray());
            exponent = Base64.getEncoder().encodeToString(((RSAPublicKey) kp.getPublic()).getPublicExponent().toByteArray());
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) kp.getPublic(), (RSAPrivateKey) kp.getPrivate());
            Map<String, Object> header_claims = new HashMap<>();
            header_claims.put("kid", keyId);
            Calendar c = Calendar.getInstance();
            Date issued_at, expires_at;
            if (expired) {
                c.add(Calendar.MINUTE, -60);
            }
            issued_at = c.getTime();
            c.add(Calendar.MINUTE, 5);
            expires_at = c.getTime();
            if (subject.isAdmin()) {
                Map<String, String[]> roles = new HashMap<>();
                roles.put("roles", new String[]{OidcAuthUtilsTest.adminClaim});
                Map<String, Map<String, String[]>> resource_access = new HashMap<>();
                resource_access.put(OidcAuthUtilsTest.clientId, roles);
                return JWT.create()
                        .withHeader(header_claims)
                        .withIssuedAt(issued_at).withExpiresAt(expires_at)
                        .withClaim("typ", "Bearer")
                        .withClaim("sub", subject.getSub())
                        .withClaim("email", subject.getEmail())
                        .withClaim("name", subject.getName())
                        .withClaim("preferred_username", subject.getPreferredUsername())
                        .withClaim("resource_access", resource_access)
                        .sign(algorithm);
            } else {
                return JWT.create()
                        .withHeader(header_claims)
                        .withIssuedAt(issued_at).withExpiresAt(expires_at)
                        .withClaim("typ", "Bearer")
                        .withClaim("sub", subject.getSub())
                        .withClaim("email", subject.getEmail())
                        .withClaim("name", subject.getName())
                        .withClaim("preferred_username", subject.getPreferredUsername())
                        .sign(algorithm);
            }
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

}
