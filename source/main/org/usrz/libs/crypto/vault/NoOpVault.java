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

import org.usrz.libs.utils.codecs.CharsetCodec;
import org.usrz.libs.utils.codecs.Codec;

public class NoOpVault implements Vault {

    public static final Vault NO_OP_VAULT = new NoOpVault();

    private static final Codec CODEC = new CharsetCodec(UTF8);

    private NoOpVault() {
        /* Nothing to do */
    }

    @Override
    public void close() {
        /* Nothing to do */
    }

    @Override
    public boolean isDestroyed() {
        return false;
    }

    @Override
    public boolean canEncrypt() {
        return false;
    }

    @Override
    public boolean canDecrypt() {
        return false;
    }

    @Override
    public Codec getCodec() {
        return CODEC;
    }

    @Override
    public byte[] encryptBytes(byte[] data) {
        return data;
    }

    @Override
    public byte[] decrypt(byte[] data) {
        return data;
    }

}
