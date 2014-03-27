/* ========================================================================== *
 * Copyright 2014 USRZ.com and Pier Paolo Fumagalli                           *
 * -------------------------------------------------------------------------- *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *  http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 * ========================================================================== */
package org.usrz.libs.crypto.json;

import static org.usrz.libs.utils.Charsets.UTF8;
import static org.usrz.libs.utils.codecs.Base64Codec.Alphabet.URL_SAFE;

import org.testng.annotations.Test;
import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.utils.codecs.Base64Codec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonWebSignatureTest extends AbstractTest {

    private final ObjectMapper mapper = new ObjectMapper() {
        @Override
        public String writeValueAsString(Object object)
        throws JsonProcessingException {
            final String string = super.writeValueAsString(object);
            return string.replace(",", ",\r\n ");
        }
    };

    private final JsonWebTokenManager signer = new JsonWebTokenManager(Hash.SHA256, mapper);

    private final byte[] key;

    public JsonWebSignatureTest() {
        final int[] intKey = new int[] { 3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
                143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
                46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
                98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
                208, 128, 163 };
        key = new byte[intKey.length];
        for (int x = 0; x < key.length; x ++) key[x] = (byte) intKey[x];
    }

    @Test
    public void testIETFDraft()
    throws Exception {
        final Tester tester = new Tester("joe", 1300819380, true);

        final Base64Codec codec = new Base64Codec(URL_SAFE, false);

        final String string = mapper.writeValueAsString(tester);
        assertEquals(string, "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}", "Jackson wrote something wrong");


        final String encoded = codec.encode(string.getBytes(UTF8));
        assertEquals(encoded, "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", "Base64 encoding is wrong");

        final String token = signer.create(tester, key);
        assertEquals(token, "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

        final Tester parsed = signer.parse(token, key, Tester.class);

        assertNotNull(parsed);
        assertEquals(parsed.getString(), tester.getString(), "Wrong 'iss'");
        assertEquals(parsed.getNumber(), tester.getNumber(), "Wrong 'exp'");
        assertEquals(parsed.getBoolean(), tester.getBoolean(), "Wrong 'http://example.com/is_root'");
    }

    @Test(expectedExceptions=IllegalArgumentException.class, expectedExceptionsMessageRegExp="Not enough components in token .*")
    public void testShortHeader() {
        signer.parse("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ", key, Tester.class);
    }

    @Test(expectedExceptions=IllegalArgumentException.class, expectedExceptionsMessageRegExp="Too many components in token .*")
    public void testLongHeader() {
        signer.parse("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk.foo", key, Tester.class);
    }

    @Test(expectedExceptions=IllegalArgumentException.class, expectedExceptionsMessageRegExp="Invalid header type \"XXX\" for token .*")
    public void testInvalidType() {
        signer.parse("eyJ0eXAiOiJYWFgiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", key, Tester.class);
    }

    @Test(expectedExceptions=IllegalArgumentException.class, expectedExceptionsMessageRegExp="Invalid header algorithm \"HELLO\" for token .*")
    public void testInvalidAlgorithm() {
        signer.parse("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIRUxMTyJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", key, Tester.class);
    }

    @Test(expectedExceptions=IllegalArgumentException.class, expectedExceptionsMessageRegExp="Unable to parse header contents for token .*")
    public void testInvalidHeader() {
        signer.parse("eyJmb28iOiJCQVIiLA0KICJobG8iOiJXT1JMRCJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", key, Tester.class);
    }

    @Test(expectedExceptions=IllegalArgumentException.class, expectedExceptionsMessageRegExp="Unable to parse payload contents for token .*")
    public void testInvalidPayload() {
        signer.parse("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJhYmMiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.q7FAR9tug3ivpZbP-tW4ftqUK0wXJH8pzdrOXLv5xWo", key, Tester.class);
    }

    @Test(expectedExceptions=IllegalArgumentException.class, expectedExceptionsMessageRegExp="Unable to verify signature for token .*")
    public void testInvalidSignature() {
        signer.parse("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXK", key, Tester.class);
    }

    /* ====================================================================== */

    @JsonPropertyOrder({ "iss", "exp", "http://example.com/is_root"})
    public static final class Tester {

        private final String s;
        private final int n;
        private final boolean b;

        @JsonCreator
        public Tester(@JsonProperty("iss") String s,
                      @JsonProperty("exp") int n,
                      @JsonProperty("http://example.com/is_root") boolean b) {
            this.s = s;
            this.n = n;
            this.b = b;
        }

        @JsonProperty("iss")
        public String getString() {
            return s;
        }

        @JsonProperty("exp")
        public int getNumber() {
            return n;
        }

        @JsonProperty("http://example.com/is_root")
        public boolean getBoolean() {
            return b;
        }
    }
}
