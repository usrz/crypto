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
import static org.usrz.libs.utils.Check.notNull;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.security.GeneralSecurityException;

import org.bouncycastle.util.Arrays;
import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.utils.codecs.Codec;

public interface Vault extends ClosingDestroyable {

    public enum Type { AES, NONE };

    public boolean canEncrypt();

    public boolean canDecrypt();

    public Codec getCodec();

    /* ====================================================================== */

    default String encrypt(String string)
    throws GeneralSecurityException {
        return this.encrypt(notNull(string, "Null string to encrypt").getBytes(UTF8));
    }

    default String encrypt(byte[] data)
    throws GeneralSecurityException {
        return getCodec().encode(encryptBytes(notNull(data, "No data to encrypt")));
    }

    public byte[] encryptBytes(byte[] data)
    throws GeneralSecurityException;

    /* ====================================================================== */

    public byte[] decrypt(byte[] data)
    throws GeneralSecurityException;

    default byte[] decrypt(String string)
    throws GeneralSecurityException {
        return decrypt(getCodec().decode(string));
    }

    default char[] decryptCharacters(String string)
    throws GeneralSecurityException {
        final byte[] bytes = decrypt(string);
        final CharsetDecoder decoder = UTF8.newDecoder();
        try {
            return decoder.decode(ByteBuffer.wrap(bytes)).array();
        } catch (CharacterCodingException exception) {
            throw new IllegalArgumentException("Unable to decode UTF8 string", exception);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

}
