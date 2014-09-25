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
import org.usrz.libs.crypto.json.HashedPassword;
import org.usrz.libs.crypto.kdf.BasicKDFManager;
import org.usrz.libs.crypto.kdf.KDF;
import org.usrz.libs.crypto.kdf.KDF.Function;
import org.usrz.libs.crypto.kdf.KDFSpec;
import org.usrz.libs.crypto.kdf.KDFSpecBuilder;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.databind.ObjectMapper;

public class HashedPasswordTest extends AbstractTest {

    private ObjectMapper mapper;
    private KDFSpec spec;
    private KDF kdf;

    @BeforeTest
    public void beforeTest() {
        mapper = new ObjectMapper();
        spec = new KDFSpecBuilder(Function.OPENSSL)
                  .withIterations(1024)
                           .build();
        kdf = new BasicKDFManager().getKDF(spec);
    }

    @Test
    public void testHashedPassword()
    throws Exception {
        final Password password1 = new Password("IrkWneuEPDciNs6DbibjL4uelUtZYaSqE8KPKxR1epd2zoFsqI5uKChJUDXfGIUO".toCharArray());
        final Password password2 = new Password("iQ4kZC2YcH0Kc6KH8bxVG7RtOv0RYlYv529mdUG2tI9LlNlvJPFlNkX5t41yxfRC".toCharArray());

        final HashedPassword hashed = new HashedPassword(kdf, password1);
        assertTrue(hashed.validate(kdf, password1));
        assertFalse(hashed.validate(kdf, password2));

        final String json = mapper.writer().withFeatures(INDENT_OUTPUT).writeValueAsString(hashed);
        log.debug("JSON Format:\n%s", json);
        final HashedPassword parsed = mapper.readValue(json, HashedPassword.class);

        assertEquals(parsed.getHash(), hashed.getHash());
        assertEquals(parsed.getSalt(), hashed.getSalt());
        assertEquals(parsed.getKDFSpec(), hashed.getKDFSpec());

        assertTrue(parsed.validate(kdf, password1));
        assertFalse(parsed.validate(kdf, password2));

        password1.close();
        password2.close();
        hashed.close();
        parsed.close();

        assertEquals(hashed.getKDFSpec(), spec);
        assertEquals(parsed.getKDFSpec(), spec);
        assertException(() -> hashed.getHash(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getHash(), IllegalStateException.class, "Destroyed");
        assertException(() -> hashed.getSalt(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getSalt(), IllegalStateException.class, "Destroyed");
        assertException(() -> hashed.validate(kdf, password1), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.validate(kdf, password1), IllegalStateException.class, "Destroyed");
    }
}