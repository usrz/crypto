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
import org.usrz.libs.crypto.kdf.KDF.Function;
import org.usrz.libs.crypto.kdf.KDFSpecBuilder;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.Crypto.Algorithm;
import org.usrz.libs.crypto.vault.CryptoBuilder;
import org.usrz.libs.crypto.vault.CryptoSpec;
import org.usrz.libs.crypto.vault.CryptoSpecBuilder;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.databind.ObjectMapper;

public class EncryptedPasswordsTest extends AbstractTest {

    private ObjectMapper mapper;
    private CryptoSpec spec;
    private Crypto crypto;

    @BeforeTest
    public void beforeTest() {
        final Password password = new Password("ljSBDYcTAZpyAjRaDFCL2aew3x3S1uZnpAfFIE95EWCp4xpHZirwfZovtDbREiV7".toCharArray());
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
        final Password password1 = new Password("IMOPjwSdFhQi67cZLc58hNP71i0DibtvknfMKno9ohktJqdVaokpie0gp5yEWROx".toCharArray());
        final Password password2 = new Password("JsNb3RVjWD967SzBPfRIV83g6EC3Z1IBbekYBTf0oEHfFon9iXmbU2oUTrJXHSC1".toCharArray());
        final Password password3 = new Password("inRijZgyZmjRFiFS2lHKaXzkCRCwFyDFvByciDX5qNeSFIpKIopckJR9ZOWigIqP".toCharArray());

        final EncryptedPasswords encrypted = new EncryptedPasswords(crypto);
        encrypted.encrypt(crypto, "passwordX", password1); // same as P1
        encrypted.encrypt(crypto, "password1", password1);
        encrypted.encrypt(crypto, "password2", password2);
        encrypted.encrypt(crypto, "password3", password3);

        assertEquals(encrypted.decrypt(crypto, "passwordX").get(), password1.get());
        assertEquals(encrypted.decrypt(crypto, "password1").get(), password1.get());
        assertEquals(encrypted.decrypt(crypto, "password2").get(), password2.get());
        assertEquals(encrypted.decrypt(crypto, "password3").get(), password3.get());

        /* Same password encrypted twice should produce different results */
        assertNotEquals(encrypted.getEncryptedData().get("passwordX"),
                        encrypted.getEncryptedData().get("password1"));


        final String json = mapper.writer().withFeatures(INDENT_OUTPUT).writeValueAsString(encrypted);
        log.debug("JSON Format:\n%s", json);
        final EncryptedPasswords parsed = mapper.readValue(json, EncryptedPasswords.class);

        assertEquals(parsed.getEncryptedData(), encrypted.getEncryptedData());
        assertEquals(parsed.getCryptoSpec(), encrypted.getCryptoSpec());
        assertEquals(parsed.decrypt(crypto, "passwordX").get(), encrypted.decrypt(crypto, "passwordX").get());
        assertEquals(parsed.decrypt(crypto, "password1").get(), encrypted.decrypt(crypto, "password1").get());
        assertEquals(parsed.decrypt(crypto, "password2").get(), encrypted.decrypt(crypto, "password2").get());
        assertEquals(parsed.decrypt(crypto, "password3").get(), encrypted.decrypt(crypto, "password3").get());
        assertEquals(parsed.decrypt(crypto, "passwordX").get(), password1.get());
        assertEquals(parsed.decrypt(crypto, "password1").get(), password1.get());
        assertEquals(parsed.decrypt(crypto, "password2").get(), password2.get());
        assertEquals(parsed.decrypt(crypto, "password3").get(), password3.get());

        password1.close();
        password2.close();
        password3.close();
        encrypted.close();
        parsed.close();

        assertEquals(encrypted.getCryptoSpec(), spec);
        assertEquals(parsed.getCryptoSpec(), spec);

        assertException(() -> encrypted.getEncryptedData(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncryptedData(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.decrypt(crypto, "password1"), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.decrypt(crypto, "password1"), IllegalStateException.class, "Destroyed");
    }
}