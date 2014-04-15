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

import java.security.GeneralSecurityException;

import org.usrz.libs.utils.codecs.Codec;

public interface Vault {

    public enum Type { AES };

    public boolean canEncrypt();

    public boolean canDecrypt();

    default String encrypt(String string)
    throws GeneralSecurityException {
        return this.encrypt(notNull(string, "Null string to encrypt").getBytes(UTF8));
    }

    public String encrypt(byte[] data)
    throws GeneralSecurityException;

    public byte[] decrypt(String string)
    throws GeneralSecurityException;

    default String decode(String string)
    throws GeneralSecurityException {
        return new String(decrypt(string), UTF8);
    }

    public Codec getCodec();

}
