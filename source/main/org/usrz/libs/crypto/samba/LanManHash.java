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
package org.usrz.libs.crypto.samba;

import static org.usrz.libs.crypto.utils.CryptoUtils.destroyArray;
import static org.usrz.libs.crypto.utils.CryptoUtils.safeEncode;
import static org.usrz.libs.utils.Charsets.ISO8859_1;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.usrz.libs.utils.Check;

public class LanManHash implements SambaHash {

    private static final byte[] SECRET = "KGS!@#$%".getBytes(ISO8859_1);

    private final Charset charset;

    public LanManHash() {
        this(ISO8859_1);
    }

    public LanManHash(Charset charset) {
        this.charset = Check.notNull(charset, "Null charset");
    }

    @Override
    public byte[] hashPassword(char[] password) {
        final char[] upperCase = new char[password.length];
        for (int x = 0; x < password.length; x ++) {
            upperCase[x] = Character.toUpperCase(password[x]);
        }

        final byte[] bytes = safeEncode(upperCase, true, charset);

        final byte[] hash = new byte[16], key = new byte[8];
        try {
            final Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
            final Key lkey = new SecretKeySpec(generateKey(bytes, 0, key), "DES");
            des.init(Cipher.ENCRYPT_MODE, lkey);
            des.update(SECRET, 0, SECRET.length, hash, 0);

            final Key hkey = new SecretKeySpec(generateKey(bytes, 7, key), "DES");
            des.init(Cipher.ENCRYPT_MODE, hkey);
            des.update(SECRET, 0, SECRET.length, hash, 8);

        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to generate hash", exception);
        } finally {
            destroyArray(bytes);
            destroyArray(key);
        }

        return hash;
    }

    /* ====================================================================== */

    private static final byte[] generateKey(byte[] bytes, int offset, byte[] key) {
        long number = 0;
        for (int position = offset, shift = 56, count = 0;
             (position < bytes.length) && (count < 8);
             position ++, shift -= 8, count ++) {
            number |= ((bytes[position] & 0x0FFL) << shift);
        }

        final byte[] tmp = new byte[8];
        tmp[0] = (byte) ((number >> 56) & 0x0ff);
        tmp[1] = (byte) ((number >> 48) & 0x0ff);
        tmp[2] = (byte) ((number >> 40) & 0x0ff);
        tmp[3] = (byte) ((number >> 32) & 0x0ff);
        tmp[4] = (byte) ((number >> 24) & 0x0ff);
        tmp[5] = (byte) ((number >> 16) & 0x0ff);
        tmp[6] = (byte) ((number >>  8) & 0x0ff);
        tmp[7] = (byte)  (number        & 0x0ff);

        number = (number & 0xFFFFFFFFFFFFFF00L) | ((number & (0x07FL <<  8)) >> 7);
        number = (number & 0xFFFFFFFFFFFF00FFL) | ((number & (0x07FL << 15)) >> 6);
        number = (number & 0xFFFFFFFFFF00FFFFL) | ((number & (0x07FL << 22)) >> 5);
        number = (number & 0xFFFFFFFF00FFFFFFL) | ((number & (0x07FL << 29)) >> 4);
        number = (number & 0xFFFFFF00FFFFFFFFL) | ((number & (0x07FL << 36)) >> 3);
        number = (number & 0xFFFF00FFFFFFFFFFL) | ((number & (0x07FL << 43)) >> 2);
        number = (number & 0xFF00FFFFFFFFFFFFL) | ((number & (0x07FL << 50)) >> 1);
        number = (number & 0xFEFFFFFFFFFFFFFFL);

        key[0] = (byte) ((number >> 56) & 0x0ff);
        key[1] = (byte) ((number >> 48) & 0x0ff);
        key[2] = (byte) ((number >> 40) & 0x0ff);
        key[3] = (byte) ((number >> 32) & 0x0ff);
        key[4] = (byte) ((number >> 24) & 0x0ff);
        key[5] = (byte) ((number >> 16) & 0x0ff);
        key[6] = (byte) ((number >>  8) & 0x0ff);
        key[7] = (byte)  (number        & 0x0ff);

        number = 0;

        return key;
    }

}
