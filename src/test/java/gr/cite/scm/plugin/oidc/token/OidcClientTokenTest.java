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

import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;

public class OidcClientTokenTest {

    @Mock
    private OidcClientTokensStore clientTokensStore;

    @InjectMocks
    private OidcClientTokenIssuer clientTokenIssuer;

    private String testSubject = "test";
    private String testIdentificationTokenRawBody = "test-body";
    private OidcClientTokensStore.Token testIdentificationToken;
    private OidcClientTokensStore.Token expiredTestIdentificationToken = new OidcClientTokensStore.Token(testIdentificationTokenRawBody, testSubject, System.currentTimeMillis() - 10000000, 1);

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);

        OidcClientTokensStore.Tokens tokens = new OidcClientTokensStore.Tokens();

        OidcClientTokensStore.Config config = new OidcClientTokensStore.Config();
        OidcClientTokensStore.ConfigRecord configRecord = new OidcClientTokensStore.ConfigRecord(0, testSubject);
        config.setConfigRecordList(Collections.singletonList(configRecord));

        tokens.setConfig(config);

        when(clientTokensStore.get()).thenReturn(tokens);

        this.testIdentificationToken = new OidcClientTokensStore.Token(clientTokenIssuer.hash(testSubject, testIdentificationTokenRawBody), testSubject, System.currentTimeMillis(), 0);
        tokens.setTokenList(Collections.singletonList(testIdentificationToken));
    }

    @Test
    public void shouldValidateTokenBody() {
        String testHash = clientTokenIssuer.hash(testSubject, testIdentificationTokenRawBody);
        assertTrue("Failure - The hash should have been approved", clientTokenIssuer.checkHash(testSubject, testHash, testIdentificationTokenRawBody));
    }

    @Test
    public void shouldNotValidateTokenBody() {
        assertFalse("Failure - The hash should not have been approved", clientTokenIssuer.checkHash(testSubject, "this-hash-is-wrong", testIdentificationTokenRawBody));
    }

    @Test
    public void shouldBeValid() {
        assertTrue("Failure - The token should be valid", testIdentificationToken.isValid());
    }

    @Test
    public void shouldBeInvalid() {
        assertFalse("Failure - The token should be invalid", expiredTestIdentificationToken.isValid());
    }

    @Test
    public void shouldBelongToTheUser() {
        assertEquals("Failure - The token should correspond to the user", testSubject, clientTokenIssuer.getUserByToken(testIdentificationTokenRawBody));
    }

    @Test
    public void shouldReturnUserTokens() {
        assertEquals("Failure - User tokens were not fetched correctly", 1, clientTokenIssuer.getUserTokens(testSubject).size());
    }

}
