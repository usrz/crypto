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

import static org.usrz.libs.crypto.utils.CryptoUtils.safeEncode;
import static org.usrz.libs.utils.Check.notNull;

import java.security.GeneralSecurityException;

import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.crypto.utils.CryptoUtils;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.CryptoSpec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EncryptedPassword implements ClosingDestroyable {

    private boolean destroyed;
    private final CryptoSpec spec;
    private final byte[] data;

    @JsonCreator
    public EncryptedPassword(@JsonProperty("spec") CryptoSpec spec,
                             @JsonProperty("data") byte[] data) {
        this.spec = notNull(spec, "Null spec");
        this.data = notNull(data, "Null data");
    }

    @JsonIgnore
    public EncryptedPassword(Crypto crypto, Password password) {
        byte[] bytes = null;
        try {
            bytes = safeEncode(password.get(), false);
            spec = crypto.getSpec();
            data = crypto.encrypt(bytes);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Exception encrypting", exception);
        } finally {
            CryptoUtils.destroyArray(bytes);
        }
    }

    /* ====================================================================== */

    @JsonProperty("spec")
    public CryptoSpec getCryptoSpec() {
        return spec;
    }

    @JsonProperty("data")
    public byte[] getEncryptedData() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        return data;
    }

    /* ====================================================================== */

    @JsonIgnore
    public Password decrypt(Crypto crypto) {
        if (destroyed) throw new IllegalStateException("Destroyed");

        /* Check the KDF spec we got */
        if (!crypto.getSpec().equals(getCryptoSpec()))
            throw new IllegalArgumentException("Crypto spec mismatch");

        /* Decrypt the password */
        try {
            final byte[] bytes = crypto.decrypt(data);
            final char[] chars = CryptoUtils.safeDecode(bytes, true);
            return new Password(chars);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Exception decrypting", exception);
        }

    }

    /* ====================================================================== */

    @Override
    public void close() {
        if (! destroyed) try {
            CryptoUtils.destroyArray(data);
        } finally {
            destroyed = true;
        }
    }

    @Override
    @JsonIgnore
    public final boolean isDestroyed() {
        return destroyed;
    }

}
