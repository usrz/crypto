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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.crypto.utils.KeyCert;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.CryptoSpec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EncryptedKeyCert extends EncryptedKeyPair implements ClosingDestroyable {

    private final byte[] certificate;
    private final String certificateType;

    @JsonCreator
    public EncryptedKeyCert(@JsonProperty("spec") CryptoSpec spec,
                            @JsonProperty("private_key") byte[] privateKey,
                            @JsonProperty("private_key_format") String privateKeyFormat,
                            @JsonProperty("public_key")  byte[] publicKey,
                            @JsonProperty("public_key_format")  String publicKeyFormat,
                            @JsonProperty("certificate")  byte[] certificate,
                            @JsonProperty("certificate_type")  String certificateType,
                            @JsonProperty("algorithm")  String algorithm) {
        super(spec, privateKey, privateKeyFormat, publicKey, publicKeyFormat, algorithm);
        this.certificate  = notNull(certificate,  "Null certificate");
        this.certificateType  = notNull(certificateType,  "Null certificate format");
    }

    @JsonIgnore
    public EncryptedKeyCert(Crypto crypto, KeyCert keyCert) {
        this(crypto, keyCert.getPrivate(), keyCert.getCertificate());
    }

    @JsonIgnore
    public EncryptedKeyCert(Crypto crypto, PrivateKey privateKey, Certificate certificate) {
        super(crypto, privateKey, certificate.getPublicKey());
        try {
            this.certificate = certificate.getEncoded();
            certificateType = certificate.getType();
        } catch (CertificateEncodingException exception) {
            throw new IllegalArgumentException("Error encoding certificate", exception);
        }
    }

    /* ====================================================================== */

    @JsonProperty("certificate")
    public final byte[] getEncodedCertificate() {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");
        return certificate;
    }

    @JsonProperty("certificate_type")
    public final String getEncodedCertificateType() {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");
        return certificateType;
    }

    /* ====================================================================== */

    @JsonIgnore
    public final Certificate decodeCertificate() {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");

        final InputStream input = new ByteArrayInputStream(certificate);
        try {
            final CertificateFactory factory = CertificateFactory.getInstance(certificateType);
            return factory.generateCertificate(input);
        } catch (CertificateException exception) {
            throw new IllegalStateException("Exception decoding public key", exception);
        } finally {
            try {
                input.close();
            } catch (IOException exception) {
                throw new IllegalStateException("I/O error closing byte array input stream?", exception);
            }
        }
    }

    @JsonIgnore
    public KeyCert decryptKeyCert(Crypto crypto) {
        if (isDestroyed()) throw new IllegalStateException("Destroyed");
        return new KeyCert(decodeCertificate(), decryptPrivateKey(crypto));
    }
}
