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
package org.usrz.libs.crypto.utils;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.usrz.libs.utils.Charsets.UTF8;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.usrz.libs.utils.codecs.CharsetCodec;
import org.usrz.libs.utils.codecs.Codec;
import org.usrz.libs.utils.codecs.HexCodec;

/**
 * A simple utility class to produce {@link StringCipher}s, capable of
 * encrypting and decrypting {@link String}s.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class StringCipherBuilder {

    private String algorithm;
    private Codec inputCodec;
    private Codec outputCodec;
    private byte[] initializationVector;
    private Key key;

    /**
     * Create a new {@link StringCipherBuilder} associated with the default
     * <em>RSA</em> algorithm.
     */
    public StringCipherBuilder() {
        this("RSA");
    }

    /**
     * Create a new {@link StringCipherBuilder} associated with the specified
     * algorithm.
     *
     * @see #withAlgorithm(String)
     */
    public StringCipherBuilder(String algorithm) {
        withAlgorithm(algorithm);
    }

    /**
     * Create a new {@link StringCipher} encrypting strings.
     */
    public StringCipher encipher() {
        if (key == null) throw new IllegalStateException("Key not specified");
        if (inputCodec == null) inputCodec = new CharsetCodec(UTF8);
        if (outputCodec == null) outputCodec = new HexCodec();
        try {
            return new StringCipherImpl(this, ENCRYPT_MODE);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to create cipher", exception);
        }
    }

    /**
     * Create a new {@link StringCipher} decrypting strings.
     */
    public StringCipher decipher() {
        if (key == null) throw new IllegalStateException("Key not specified");
        if (outputCodec == null) outputCodec = new CharsetCodec(UTF8);
        if (inputCodec == null) inputCodec = new HexCodec();
        try {
            return new StringCipherImpl(this, DECRYPT_MODE);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to create cipher", exception);
        }
    }

    /**
     * Specify the name of the algorithm used by this
     * {@link StringCipherBuilder}.
     */
    public StringCipherBuilder withAlgorithm(String algorithm) {
        if (algorithm == null) throw new NullPointerException("Null algorithm");
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Specify the {@link Key} used for encryption or decryption.
     *
     * <p>If the algorithm is <em>symmetric</em> then a {@link SecretKey}
     * should be specified, otherwise this method should be passed either a
     * {@link PublicKey} or {@link PrivateKey} depending on whether we are
     * {@linkplain #encipher() encrypting} or
     * {@linkplain #decipher() decrypting} (respectively).</p>
     */
    public StringCipherBuilder withKey(Key key) {
        if (key == null) throw new NullPointerException("Null key");
        this.key = key;
        return this;
    }

    /**
     * Specify the output {@link Codec} for the
     * {@linkplain StringCipher#transform(String) transformation}.
     *
     * <p>By default this will be set to a {@link HexCodec} when decrypting
     * or a {@link CharsetCodec} <em>(UTF-8)</em> when encrypting.
     */
    public StringCipherBuilder withOutputCodec(Codec codec) {
        if (codec == null) throw new NullPointerException("Null codec");
        outputCodec = codec;
        return this;
    }

    /**
     * Specify the input {@link Codec} for the
     * {@linkplain StringCipher#transform(String) transformation}.
     *
     * <p>By default this will be set to a {@link HexCodec} when encrypting
     * or a {@link CharsetCodec} <em>(UTF-8)</em> when decrypting.
     */
    public StringCipherBuilder withInputCodec(Codec codec) {
        if (codec == null) throw new NullPointerException("Null codec");
        inputCodec = codec;
        return this;
    }

    /**
     * Specify the (optional) <em>initialization vector</em> to be used during
     * {@linkplain StringCipher#transform(String) transformation}.
     *
     * <p>This is useful with <b>AES</b>.</p>
     */
    public StringCipherBuilder withInitializationVector(byte[] initializationVector) {
        if (initializationVector == null) throw new NullPointerException("Null initialization vector");
        this.initializationVector = initializationVector;
        return this;
    }

    /* ====================================================================== */

    /* Get our cipher */
    private Cipher cipher(int mode)
    throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance(algorithm);
        if (initializationVector != null) {
            final IvParameterSpec spec = new IvParameterSpec(initializationVector);
            cipher.init(mode, key, spec, new SecureRandom());
        } else {
            cipher.init(mode, key, new SecureRandom());
        }
        return cipher;
    }

    /* ====================================================================== */

    private static final class StringCipherImpl implements StringCipher {

        private final StringCipherBuilder builder;
        private final int mode;
        private Cipher cipher;

        private StringCipherImpl(StringCipherBuilder builder, int mode)
        throws GeneralSecurityException {
            this.builder = builder;
            this.mode = mode;
            cipher = builder.cipher(mode);
        }

        @Override
        public String getAlgorithm() {
            return cipher.getAlgorithm();
        }

        @Override
        public byte[] getInitializationVector() {
            return cipher.getIV();
        }

        @Override
        public String transform(String string) {
            final byte[] decoded = builder.inputCodec.decode(string);
            try {
                return builder.outputCodec.encode(cipher.doFinal(decoded));
            } catch (IllegalBlockSizeException | BadPaddingException exception) {
                try {
                    /* Reset the cipher and throw */
                    cipher = builder.cipher(mode);
                    throw new IllegalArgumentException("Exception transforming", exception);
                } catch (GeneralSecurityException exception2) {
                    /* Whops, can't reset the cipher??? */
                    throw new IllegalStateException("Unable to reset cipher", exception2);
                }
            }
        }
    }
}
