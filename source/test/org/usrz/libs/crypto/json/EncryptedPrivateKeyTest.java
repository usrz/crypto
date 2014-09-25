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

import static com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.json.EncryptedPrivateKey;
import org.usrz.libs.crypto.kdf.KDF.Function;
import org.usrz.libs.crypto.kdf.KDFSpecBuilder;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.Crypto.Algorithm;
import org.usrz.libs.crypto.vault.CryptoBuilder;
import org.usrz.libs.crypto.vault.CryptoSpec;
import org.usrz.libs.crypto.vault.CryptoSpecBuilder;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.databind.ObjectMapper;

public class EncryptedPrivateKeyTest extends AbstractTest {

    private ObjectMapper mapper;
    private CryptoSpec spec;
    private Crypto crypto;

    @BeforeTest
    public void beforeTest() {
        final Password password = new Password("71xNBqjvErFqGedZ6cKn5aIWOtSyM8M5iWGRNInVzCxAi7m1wnFki7t7aeCTtCbN".toCharArray());
        mapper = new ObjectMapper();
        spec = new CryptoSpecBuilder(Algorithm.AES)
                        .withKDFSpec(new KDFSpecBuilder(Function.OPENSSL)
                                        .withIterations(1024)
                                                 .build())
                              .build();
        crypto = new CryptoBuilder(spec)
                     .withPassword(password)
                     .build();
        password.close();
    }

    @Test
    public void testEncryptedPrivateKeyRSA()
    throws Exception {
        testEncryptedPrivateKey(KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate());
    }

    @Test
    public void testEncryptedPrivateKeyDSA()
    throws Exception {
        testEncryptedPrivateKey(KeyPairGenerator.getInstance("DSA").generateKeyPair().getPrivate());
    }

    private void testEncryptedPrivateKey(PrivateKey privateKey)
    throws Exception {
        final EncryptedPrivateKey encrypted = new EncryptedPrivateKey(crypto, privateKey);
        assertEquals(encrypted.decryptPrivateKey(crypto), privateKey);

        final String json = mapper.writer().withFeatures(INDENT_OUTPUT).writeValueAsString(encrypted);
        log.debug("JSON Format:\n%s", json);
        final EncryptedPrivateKey parsed = mapper.readValue(json, EncryptedPrivateKey.class);

        assertEquals(parsed.getEncryptedPrivateKey(), encrypted.getEncryptedPrivateKey());
        assertEquals(parsed.getEncryptedPrivateKeyFormat(), encrypted.getEncryptedPrivateKeyFormat());
        assertEquals(parsed.getCryptoSpec(), encrypted.getCryptoSpec());
        assertEquals(parsed.getAlgorithm(), encrypted.getAlgorithm());

        assertEquals(parsed.decryptPrivateKey(crypto), encrypted.decryptPrivateKey(crypto));
        assertEquals(parsed.decryptPrivateKey(crypto), privateKey);

        encrypted.close();
        parsed.close();

        assertEquals(encrypted.getCryptoSpec(), spec);
        assertEquals(parsed.getCryptoSpec(), spec);

        assertException(() -> encrypted.getAlgorithm(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncryptedPrivateKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncryptedPrivateKeyFormat(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.decryptPrivateKey(crypto), IllegalStateException.class, "Destroyed");

        assertException(() -> parsed.getAlgorithm(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncryptedPrivateKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncryptedPrivateKeyFormat(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.decryptPrivateKey(crypto), IllegalStateException.class, "Destroyed");
    }
}