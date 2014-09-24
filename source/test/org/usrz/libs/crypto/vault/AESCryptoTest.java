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
import static org.usrz.libs.utils.codecs.Base64Codec.BASE_64;

import java.security.GeneralSecurityException;

import org.testng.annotations.Test;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.crypto.kdf.KDF;
import org.usrz.libs.crypto.kdf.PBKDF2;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.utils.codecs.Codec;

public class AESCryptoTest extends AbstractTest {

    @Test
    public void testAESVault()
    throws GeneralSecurityException {
        final Codec codec = BASE_64;
        final KDF kdf = new PBKDF2(Hash.SHA1, 10000, 32);
        final Password password = new Password("foobarbaz".toCharArray());
        final AESCrypto vault = new AESCrypto(kdf, password);
        password.close();


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
            assertEquals(exception.getMessage(), "Vault destroyed");
        }
    }

}
