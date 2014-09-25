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

import java.util.Arrays;

import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.kdf.KDF;
import org.usrz.libs.crypto.kdf.KDFSpec;
import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.crypto.utils.CryptoUtils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class HashedPassword implements ClosingDestroyable {

    private boolean destroyed;
    private final KDFSpec spec;
    private final byte[] hash;
    private final byte[] salt;

    @JsonCreator
    public HashedPassword(@JsonProperty("spec") KDFSpec spec,
                          @JsonProperty("hash") byte[] hash,
                          @JsonProperty("salt") byte[] salt) {
        this.spec = notNull(spec, "Null spec");
        this.hash = notNull(hash, "Null hash");
        this.salt = notNull(salt, "Null salt");
        destroyed = false;
    }

    @JsonIgnore
    public HashedPassword(KDF kdf, Password password) {
        byte[] bytes = null;
        try {
            bytes = safeEncode(password.get(), false);
            spec = kdf.getKDFSpec();
            salt = CryptoUtils.randomBytes(spec.getDerivedKeyLength());
            hash = kdf.deriveKey(bytes, salt);
        } finally {
            CryptoUtils.destroyArray(bytes);
        }
    }

    /* ====================================================================== */

    @JsonProperty("spec")
    public KDFSpec getKDFSpec() {
        return spec;
    }

    @JsonProperty("hash")
    public byte[] getHash() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        return hash;
    }

    @JsonProperty("salt")
    public byte[] getSalt() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        return salt;
    }

    /* ====================================================================== */

    @JsonIgnore
    public boolean validate(KDF kdf, Password password) {
        if (destroyed) throw new IllegalStateException("Destroyed");

        /* Check the KDF spec we got */
        if (!kdf.getKDFSpec().equals(getKDFSpec()))
            throw new IllegalArgumentException("KDF spec mismatch");

        /* Hash the password */
        byte[] bytes = null;
        byte[] check = null;
        try {
            bytes = safeEncode(password.get(), false);
            check = kdf.deriveKey(bytes, getSalt());
            return Arrays.equals(check, getHash());
        } finally {
            CryptoUtils.destroyArray(bytes);
            CryptoUtils.destroyArray(check);
        }
    }

    /* ====================================================================== */

    @Override
    public void close() {
        if (! destroyed) try {
            CryptoUtils.destroyArray(hash);
            CryptoUtils.destroyArray(salt);
        } finally {
            destroyed = true;
        }
    }

    @Override
    @JsonIgnore
    public boolean isDestroyed() {
        return destroyed;
    }

}
