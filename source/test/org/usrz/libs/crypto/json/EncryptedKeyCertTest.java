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

import static com.fasterxml.jackson.databind.SerializationFeature.INDENT_OUTPUT;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.cert.X509CertificateBuilder;
import org.usrz.libs.crypto.json.EncryptedKeyCert;
import org.usrz.libs.crypto.kdf.KDF.Function;
import org.usrz.libs.crypto.kdf.KDFSpecBuilder;
import org.usrz.libs.crypto.utils.KeyCert;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.Crypto.Algorithm;
import org.usrz.libs.crypto.vault.CryptoBuilder;
import org.usrz.libs.crypto.vault.CryptoSpec;
import org.usrz.libs.crypto.vault.CryptoSpecBuilder;
import org.usrz.libs.testing.AbstractTest;

import com.fasterxml.jackson.databind.ObjectMapper;

public class EncryptedKeyCertTest extends AbstractTest {

    private ObjectMapper mapper;
    private CryptoSpec spec;
    private Crypto crypto;

    @BeforeTest
    public void beforeTest() {
        final Password password = new Password("71xNBqjvErFqGedZ6cKn5aIWOtSyM8M5iWGRNInVzCxAi7m1wnFki7t7aeCTtCbN".toCharArray());
        mapper = new ObjectMapper();
        spec = new CryptoSpecBuilder(Algorithm.AES)
                        .withKDFSpec(new KDFSpecBuilder(Function.OPENSSL)
                                        .withIterations(1024)
                                                 .build())
                              .build();
        crypto = new CryptoBuilder(spec)
                     .withPassword(password)
                     .build();
        password.close();
    }

    @Test
    public void testEncryptedKeyCertRSA()
    throws Exception {
        final KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final X509Certificate certificate = new X509CertificateBuilder().selfSigned("CN=test", keyPair).build();
        testEncryptedKeyCert(new KeyCert(certificate, keyPair.getPrivate()));
    }

    @Test
    public void testEncryptedKeyCertDSA()
    throws Exception {
        final KeyPair keyPair = KeyPairGenerator.getInstance("DSA").generateKeyPair();
        final X509Certificate certificate = new X509CertificateBuilder().selfSigned("CN=test", keyPair).build();
        testEncryptedKeyCert(new KeyCert(certificate, keyPair.getPrivate()));
    }

    private void testEncryptedKeyCert(KeyCert keyCert)
    throws Exception {
        final EncryptedKeyCert encrypted = new EncryptedKeyCert(crypto, keyCert);
        assertEquals(encrypted.decryptPrivateKey(crypto), keyCert.getPrivate());
        assertEquals(encrypted.decodePublicKey(), keyCert.getPublic());
        assertEquals(encrypted.decodeCertificate(), keyCert.getCertificate());

        final String json = mapper.writer().withFeatures(INDENT_OUTPUT).writeValueAsString(encrypted);
        log.debug("JSON Format:\n%s", json);
        final EncryptedKeyCert parsed = mapper.readValue(json, EncryptedKeyCert.class);

        assertEquals(parsed.getEncryptedPrivateKey(), encrypted.getEncryptedPrivateKey());
        assertEquals(parsed.getEncryptedPrivateKeyFormat(), encrypted.getEncryptedPrivateKeyFormat());
        assertEquals(parsed.getEncodedPublicKey(), encrypted.getEncodedPublicKey());
        assertEquals(parsed.getEncodedPublicKeyFormat(), encrypted.getEncodedPublicKeyFormat());
        assertEquals(parsed.getEncodedCertificate(), encrypted.getEncodedCertificate());
        assertEquals(parsed.getEncodedCertificateType(), encrypted.getEncodedCertificateType());
        assertEquals(parsed.getCryptoSpec(), encrypted.getCryptoSpec());
        assertEquals(parsed.getAlgorithm(), encrypted.getAlgorithm());

        assertEquals(parsed.decryptPrivateKey(crypto), encrypted.decryptPrivateKey(crypto));
        assertEquals(parsed.decodePublicKey(), encrypted.decodePublicKey());
        assertEquals(parsed.decodeCertificate(), encrypted.decodeCertificate());
        assertEquals(parsed.decryptPrivateKey(crypto), keyCert.getPrivate());
        assertEquals(parsed.decodePublicKey(), keyCert.getPublic());
        assertEquals(parsed.decodeCertificate(), keyCert.getCertificate());

        encrypted.close();
        parsed.close();

        assertEquals(encrypted.getCryptoSpec(), spec);
        assertEquals(parsed.getCryptoSpec(), spec);

        assertException(() -> encrypted.getAlgorithm(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncryptedPrivateKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncryptedPrivateKeyFormat(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncodedPublicKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncodedPublicKeyFormat(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncodedCertificate(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.getEncodedCertificateType(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.decryptPrivateKey(crypto), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.decodePublicKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> encrypted.decodeCertificate(), IllegalStateException.class, "Destroyed");

        assertException(() -> parsed.getAlgorithm(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncryptedPrivateKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncryptedPrivateKeyFormat(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncodedPublicKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncodedPublicKeyFormat(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncodedCertificate(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.getEncodedCertificateType(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.decryptPrivateKey(crypto), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.decodePublicKey(), IllegalStateException.class, "Destroyed");
        assertException(() -> parsed.decodeCertificate(), IllegalStateException.class, "Destroyed");
    }
}