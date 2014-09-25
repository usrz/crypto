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

import static org.usrz.libs.utils.Check.notNull;

import java.security.GeneralSecurityException;

import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.utils.CryptoUtils;
import org.usrz.libs.utils.Check;
import org.usrz.libs.utils.codecs.Codec;
import org.usrz.libs.utils.codecs.ManagedCodec;

public class Vault implements Crypto {

    private final Crypto crypto;
    private final Codec codec;
    private final VaultSpec spec;

    /* ====================================================================== */

    public Vault(Crypto crypto, ManagedCodec codec) {
        this.crypto = Check.notNull(crypto, "Null crypto");
        this.codec = notNull(codec, "Null codec");

        final CryptoSpec spec = crypto.getSpec();
        final String codecSpec = codec.getCodecSpec();
        switch (spec.getAlgorithm()) {
            case AES:
                final AESCryptoSpec aesSpec = (AESCryptoSpec) spec;
                this.spec = new AESVaultSpec(aesSpec.getKDFSpec(), codecSpec);
                break;
            case RSA:
                this.spec = new RSAVaultSpec(codecSpec);
                break;
            default:
                throw new IllegalStateException("Unsupported algorithm " + spec.getAlgorithm());
        }
    }

    /* ====================================================================== */

    @Override
    public VaultSpec getSpec() {
        return spec;
    }

    public Codec getCodec() {
        return codec;
    }

    public String encryptPassword(Password password)
    throws GeneralSecurityException {
        final byte[] bytes = CryptoUtils.safeEncode(password.get(), false);
        try {
            return getCodec().encode(encrypt(bytes));
        } finally {
            CryptoUtils.destroyArray(bytes);
        }
    }

    public Password decryptPassword(String string)
    throws GeneralSecurityException {
        final byte[] bytes = getCodec().decode(string);
        try {
            return new Password(CryptoUtils.safeDecode(decrypt(bytes), false));
        } finally {
            CryptoUtils.destroyArray(bytes);
        }
    }

    /* ====================================================================== */

    @Override
    public void close() {
        crypto.close();
    }

    @Override
    public boolean isDestroyed() {
        return crypto.isDestroyed();
    }

    @Override
    public byte[] decrypt(byte[] data)
    throws GeneralSecurityException {
        return crypto.decrypt(data);
    }

    @Override
    public byte[] encrypt(byte[] data)
    throws GeneralSecurityException {
        return crypto.encrypt(data);
    }

    @Override
    public boolean canEncrypt() {
        return crypto.canEncrypt();
    }

    @Override
    public boolean canDecrypt() {
        return crypto.canDecrypt();
    }

}
