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

import static org.usrz.libs.utils.Check.notNull;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;

import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.crypto.utils.CryptoUtils;
import org.usrz.libs.crypto.utils.DestroyableEncodedKeySpec;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.CryptoSpec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EncryptedPrivateKey implements ClosingDestroyable {

    private boolean destroyed;
    private final CryptoSpec spec;
    private final byte[] privateKey;
    private final String privateKeyFormat;
    private final String algorithm;

    @JsonCreator
    public EncryptedPrivateKey(@JsonProperty("spec") CryptoSpec spec,
                               @JsonProperty("private_key") byte[] privateKey,
                               @JsonProperty("private_key_format") String privateKeyFormat,
                               @JsonProperty("algorithm")  String algorithm) {
        this.spec = notNull(spec, "Null spec");
        this.privateKey = notNull(privateKey, "Null private key");
        this.algorithm  = notNull(algorithm,  "Null algorithm");
        this.privateKeyFormat = notNull(privateKeyFormat, "Null private key format");
    }

    @JsonIgnore
    public EncryptedPrivateKey(Crypto crypto, PrivateKey privateKey) {
       byte[] bytes = null;
       try {
           spec = crypto.getSpec();
           bytes = privateKey.getEncoded();
           this.privateKey = crypto.encrypt(bytes);
           privateKeyFormat = privateKey.getFormat();
           algorithm = privateKey.getAlgorithm();
       } catch (GeneralSecurityException exception) {
           throw new IllegalStateException("Exception encrypting", exception);
       } finally {
           CryptoUtils.destroyArray(bytes);
       }
    }

    /* ====================================================================== */

    @JsonProperty("spec")
    public final CryptoSpec getCryptoSpec() {
        return spec;
    }

    @JsonProperty("algorithm")
    public final String getAlgorithm() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        return algorithm;
    }

    @JsonProperty("private_key")
    public final byte[] getEncryptedPrivateKey() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        return privateKey;
    }

    @JsonProperty("private_key_format")
    public final String getEncryptedPrivateKeyFormat() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        return privateKeyFormat;
    }

    /* ====================================================================== */

    @JsonIgnore
    public final PrivateKey decryptPrivateKey(Crypto crypto) {
        if (destroyed) throw new IllegalStateException("Destroyed");

        /* Check the KDF spec we got */
        if (!crypto.getSpec().equals(getCryptoSpec()))
            throw new IllegalArgumentException("Crypto spec mismatch");

        /* Decrypt the password */
        byte[] bytes = null;
        DestroyableEncodedKeySpec spec = null;
        try {
            bytes = crypto.decrypt(privateKey);
            spec = new DestroyableEncodedKeySpec(privateKeyFormat, bytes);
            final KeyFactory factory = KeyFactory.getInstance(algorithm);
            return factory.generatePrivate(spec.getSpec());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Exception decrypting private key", exception);
        } finally {
            CryptoUtils.destroyArray(bytes);
            if (spec != null) spec.close();
        }
    }

    /* ====================================================================== */

    @Override
    public final void close() {
        if (! destroyed) try {
            CryptoUtils.destroyArray(privateKey);
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
