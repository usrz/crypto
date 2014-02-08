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
package org.usrz.libs.crypto.utils;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;

public class StringCipherTest extends AbstractTest {

    @Test
    public void testRSA() {
        final KeyPair keyPair = new KeyPairBuilder("RSA").build();
        final String message = "This is the most wonderful message in the world!";

        final StringCipher encipher = new StringCipherBuilder("RSA").key(keyPair.getPublic()).encipher();
        final String result1 = encipher.transform(message);
        final String result2 = encipher.transform(message);

        assertNotEquals(result1, result2, "WEAK encryption");

        final StringCipher decipher = new StringCipherBuilder("RSA").key(keyPair.getPrivate()).decipher();
        final String decrypted1 = decipher.transform(result1);
        final String decrypted2 = decipher.transform(result2);

        assertEquals(decrypted1, message);
        assertEquals(decrypted2, message);
    }

    @Test
    public void testAES()
    throws Exception {
        final SecretKey aesKey = new SecretKeyBuilder("AES").build();
        final String message = "This is the second most wonderful message in the world!";

        final StringCipher encipher1 = new StringCipherBuilder("AES/CBC/PKCS5Padding").key(aesKey).encipher();
        final StringCipher encipher2 = new StringCipherBuilder("AES/CBC/PKCS5Padding").key(aesKey).encipher();
        final String result1 = encipher1.transform(message);
        final String result2 = encipher2.transform(message);

        assertNotEquals(result1, result2, "WEAK encryption");

        final StringCipher decipher1 = new StringCipherBuilder("AES/CBC/PKCS5Padding").key(aesKey).initializationVector(encipher1.getInitializationVector()).decipher();
        final StringCipher decipher2 = new StringCipherBuilder("AES/CBC/PKCS5Padding").key(aesKey).initializationVector(encipher2.getInitializationVector()).decipher();
        final String decrypted1 = decipher1.transform(result1);
        final String decrypted2 = decipher2.transform(result2);

        assertEquals(decrypted1, message);
        assertEquals(decrypted2, message);
    }
}
