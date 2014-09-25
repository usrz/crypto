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

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.json.EncryptedPassword;
import org.usrz.libs.crypto.kdf.KDF.Function;
import org.usrz.libs.crypto.kdf.KDFSpecBuilder;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.Crypto.Algorithm;
import org.usrz.libs.crypto.vault.CryptoBuilder;
import org.usrz.libs.crypto.vault.CryptoSpec;
import org.usrz.libs.crypto.vault.CryptoSpecBuilder;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.databind.ObjectMapper;

public class EncryptedPasswordTest extends AbstractTest {

    private ObjectMapper mapper;
    private CryptoSpec spec;
    private Crypto crypto;

    @BeforeTest
    public void beforeTest() {
        final Password password = new Password("7dTELvtZukYhm8G1O79js3jagTYcM4x0kMlcDvdyWmsb5ySesVLFA5ChOFyjvXBv".toCharArray());
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
    public void testEncryptedPassword()
    throws Exception {
        final Password password = new Password("nu0YpywEIEtKy6ezmdbGeFn1H15xsWqI7T2Cjagih4TXkzOWNTUsVuhxW9zI3GWK".toCharArray());

        final EncryptedPassword encrypted = new EncryptedPassword(crypto, password);
        assertEquals(encrypted.decrypt(crypto).get(), password.get());

        final String json = mapper.writer().withFeatures(INDENT_OUTPUT).writeValueAsString(encrypted);
        log.debug("JSON Format:\n%s", json);
        final EncryptedPassword parsed = mapper.readValue(json, EncryptedPassword.class);

        assertEquals(parsed.getEncryptedData(), encrypted.getEncryptedData());
        assertEquals(parsed.getCryptoSpec(), encrypted.getCryptoSpec());
        assertEquals(parsed.decrypt(crypto).get(), encrypted.decrypt(crypto).get());
        assertEquals(parsed.decrypt(crypto).get(), password.get());

        password.close();
        encrypted.close();
        parsed.close();

        assertEquals(encrypted.getCryptoSpec(), spec);
        assertEquals(parsed.getCryptoSpec(), spec);

        assertException(() -> encrypted.getEncryptedData(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncryptedData(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.decrypt(crypto), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.decrypt(crypto), IllegalStateException.class, "Destroyed");
    }
}