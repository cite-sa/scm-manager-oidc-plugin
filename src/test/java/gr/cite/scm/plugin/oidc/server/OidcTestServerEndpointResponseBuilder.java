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
package gr.cite.scm.plugin.oidc.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import gr.cite.scm.plugin.oidc.token.OidcTestToken;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class OidcTestServerEndpointResponseBuilder {

    public static String buildCertificatesEndpointResponse(OidcTestToken testToken) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> key = new HashMap<>();
        key.put("kid", testToken.getKeyId());
        key.put("kty", "RSA");
        key.put("alg", "RS256");
        key.put("use", "sig");
        key.put("n", testToken.getModulus());
        key.put("e", testToken.getExponent());
        key.put("x5c", Collections.singletonList(testToken.getX5c()));
        String keyJson = mapper.writeValueAsString(key);
        return "{\"keys\":[" + keyJson + "]}";
    }

    public static String buildTokensEndpointResponse(OidcTestToken testToken) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> token = new HashMap<>();
        token.put("access_token", testToken.getX5c());
        return mapper.writeValueAsString(token);
    }

}
