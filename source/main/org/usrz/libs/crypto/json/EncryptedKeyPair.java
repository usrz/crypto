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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.crypto.utils.CryptoUtils;
import org.usrz.libs.crypto.utils.DestroyableEncodedKeySpec;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.CryptoSpec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EncryptedKeyPair extends EncryptedPrivateKey implements ClosingDestroyable {

    private final byte[] publicKey;
    private final String publicKeyFormat;

    @JsonCreator
    public EncryptedKeyPair(@JsonProperty("spec") CryptoSpec spec,
                            @JsonProperty("private_key") byte[] privateKey,
                            @JsonProperty("private_key_format") String privateKeyFormat,
                            @JsonProperty("public_key")  byte[] publicKey,
                            @JsonProperty("public_key_format")  String publicKeyFormat,
                            @JsonProperty("algorithm")  String algorithm) {
        super(spec, privateKey, privateKeyFormat, algorithm);
        this.publicKey  = notNull(publicKey,  "Null public key");
        this.publicKeyFormat  = notNull(publicKeyFormat,  "Null public key format");
    }

    @JsonIgnore
    public EncryptedKeyPair(Crypto crypto, KeyPair keyPair) {
        this(crypto, keyPair.getPrivate(), keyPair.getPublic());
    }

    @JsonIgnore
    public EncryptedKeyPair(Crypto crypto, PrivateKey privateKey, PublicKey publicKey) {
        super(crypto, privateKey);
        CryptoUtils.validateKeys(privateKey, publicKey);
        this.publicKey = publicKey.getEncoded().clone();
        publicKeyFormat = publicKey.getFormat();
    }

    /* ====================================================================== */

    @JsonProperty("public_key")
    public final byte[] getEncodedPublicKey() {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");
        return publicKey;
    }

    @JsonProperty("public_key_format")
    public final String getEncodedPublicKeyFormat() {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");
        return publicKeyFormat;
    }

    /* ====================================================================== */

    @JsonIgnore
    public final PublicKey decodePublicKey() {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");

        final byte[] clone = publicKey.clone(); // destroyable encoded key spec WRAPS!!!
        final DestroyableEncodedKeySpec spec = new DestroyableEncodedKeySpec(publicKeyFormat, clone);
        try {
            final KeyFactory factory = KeyFactory.getInstance(getAlgorithm());
            return factory.generatePublic(spec.getSpec());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException exception) {
          throw new IllegalStateException("Exception decoding public key", exception);
        } finally {
            spec.close();
        }
    }

    @JsonIgnore
    public final KeyPair decryptKeyPair(Crypto crypto) {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");
        return new KeyPair(decodePublicKey(), decryptPrivateKey(crypto));
    }

}
