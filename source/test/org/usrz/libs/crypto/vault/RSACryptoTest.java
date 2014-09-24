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
package org.usrz.libs.crypto.vault;

import static org.usrz.libs.utils.Charsets.UTF8;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;

public class RSACryptoTest extends AbstractTest {

    @Test
    public void testRSAVault()
    throws GeneralSecurityException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        final KeyPair pair = kpg.generateKeyPair();
        final RSACrypto vault = new RSACrypto((RSAPrivateKey) pair.getPrivate(),
                                              (RSAPublicKey) pair.getPublic());

        final byte[] original = "life is beautiful, isn't it?".getBytes(UTF8);

        /* Encrypt */
        final byte[] encrypted1 = vault.encrypt(original);
        final byte[] encrypted2 = vault.encrypt(original);
        assertNotEquals(encrypted1, encrypted2);

        /* Decrypt */
        final byte[] decrypted1 = vault.decrypt(encrypted1);
        final byte[] decrypted2 = vault.decrypt(encrypted2);
        assertEquals(decrypted1, original);
        assertEquals(decrypted2, original);

        /* Destroy */
        vault.close();
        assertTrue(vault.isDestroyed());
        assertFalse(vault.canDecrypt());
        assertFalse(vault.canEncrypt());
        try {
            vault.decrypt(encrypted1);
            fail("IllegalStateException never thrown");
        } catch (IllegalStateException exception) {
            assertEquals(exception.getMessage(), "Can not decrypt");
        }
        try {
            vault.encrypt(decrypted1);
            fail("IllegalStateException never thrown");
        } catch (IllegalStateException exception) {
            assertEquals(exception.getMessage(), "Can not encrypt");
        }
    }

}
