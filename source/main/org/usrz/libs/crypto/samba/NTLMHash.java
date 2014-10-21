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
import static org.usrz.libs.utils.Charsets.UTF16LE;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.usrz.libs.crypto.utils.CryptoUtils;


public class NTLMHash implements SambaHash {

    private static final MessageDigest MD4;

    static {
        try {
            MD4 = MessageDigest.getInstance("MD4", new BouncyCastleProvider());
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Unable to get MD4 digest", exception);
        }
    }

    public NTLMHash() {
        /* Nothing to do, statically initialized */
    }

    @Override
    public byte[] hashPassword(char[] password) {
        final byte[] bytes = CryptoUtils.safeEncode(password, false, UTF16LE);
        try {
            return ((MessageDigest) MD4.clone()).digest(bytes);
        } catch (CloneNotSupportedException exception) {
            throw new IllegalStateException("Unable to hash password", exception);
        } finally {
            destroyArray(bytes);
        }
    }

}
