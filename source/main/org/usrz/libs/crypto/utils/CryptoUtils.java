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

import static org.usrz.libs.utils.Charsets.UTF8;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

public class CryptoUtils {

    private static final SecureRandom random = new SecureRandom();

    private  CryptoUtils() {
        throw new IllegalStateException("Do not construct");
    }

    /* ====================================================================== */

    public static byte[] randomBytes(int size) {
        return randomBytes(new byte[size]);
    }

    public static byte[] randomBytes(byte[] bytes) {
        random.nextBytes(bytes);
        return bytes;
    }

    /* ====================================================================== */

    public static void destroyArray(char[] array) {
        if (array == null) return;
        for (int x = 0; x < array.length; x ++)
            array[x] = (char) random.nextInt();
        Arrays.fill(array, '\0');
    }

    public static void destroyArray(byte[] array) {
        if (array == null) return;
        random.nextBytes(array);
        Arrays.fill(array, (byte) 0);
    }

    /* ====================================================================== */

    public static byte[] safeEncode(char[] chars, boolean destroy) {

        /* Allocate our temporary byte buffer */
        final CharsetEncoder encoder = UTF8.newEncoder();
        final int maxBytes = (int) Math.ceil(encoder.maxBytesPerChar());
        final byte[] bytes = new byte[chars.length * maxBytes];

        try {
            /* Wrap chars and bytes array in NIO buffers */
            final CharBuffer charBuffer = CharBuffer.wrap(chars) ;
            final ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);

            /* Convert! */
            final CoderResult result = encoder.encode(charBuffer, byteBuffer, true);

            if (result.isError()) {
                throw new IllegalArgumentException("Error encoding UTF-8: " + result);
            } else if (result.isOverflow()) {
                throw new IllegalStateException("Char buffer overflow encoding UTF-8");
            } else if (result.isUnderflow() && (charBuffer.remaining() > 0)) {
                throw new IllegalStateException("Byte buffer underflow encoding UTF-8");
            }

            /* Copy */
            final byte[] array = new byte[byteBuffer.position()];
            System.arraycopy(bytes, 0, array, 0, array.length);
            return array;

        } finally {
            if (destroy) destroyArray(chars);
            destroyArray(bytes);
        }
    }

    public static char[] safeDecode(byte[] bytes, boolean destroy) {

        /* Allocate our temporary character buffer */
        final CharsetDecoder decoder = UTF8.newDecoder();
        final int maxChars = (int) Math.ceil(decoder.maxCharsPerByte());
        final char[] chars = new char[bytes.length * maxChars];

        try {
            /* Wrap bytes and chars array in NIO buffers */
            final ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            final CharBuffer charBuffer = CharBuffer.wrap(chars) ;

            /* Convert! */
            final CoderResult result = decoder.decode(byteBuffer, charBuffer, true);

            if (result.isError()) {
                throw new IllegalArgumentException("Error decoding UTF-8: " + result);
            } else if (result.isOverflow()) {
                throw new IllegalStateException("Char buffer overflow decoding UTF-8");
            } else if (result.isUnderflow() && (byteBuffer.remaining() > 0)) {
                throw new IllegalStateException("Byte buffer underflow decoding UTF-8");
            }

            /* Copy */
            final char[] array = new char[charBuffer.position()];
            System.arraycopy(chars, 0, array, 0, array.length);
            return array;

        } finally {
            if (destroy) destroyArray(bytes);
            destroyArray(chars);
        }
    }

    /* ====================================================================== */

    public static String validateKeys(KeyPair keyPair) {
        return validateKeys(keyPair.getPrivate(), keyPair.getPublic());
    }

    public static String validateKeys(KeyCert keyCert) {
        return validateKeys(keyCert.getPrivate(), keyCert.getPublic());
    }

    public static String validateKeys(PrivateKey privateKey, PublicKey publicKey) {

        /* Check algorithm */
        final String algorithm;
        if (!privateKey.getAlgorithm().equals(publicKey.getAlgorithm())) {
            throw new IllegalArgumentException("Key alogorithm mismatch: private=" + privateKey.getAlgorithm() + ", public=" + publicKey.getAlgorithm());
        } else {
            algorithm = privateKey.getAlgorithm();
        }

        /* Check if private/public key match */
        if ("RSA".equals(algorithm)) {
            final BigInteger privateModulus = ((RSAPrivateKey) privateKey).getModulus();
            final BigInteger publicModulus = ((RSAPublicKey) publicKey).getModulus();
            if (!privateModulus.equals(publicModulus)) {
                throw new IllegalArgumentException("RSA private/public keys modulus mismatch");
            }
        } else if ("DSA".equals(algorithm)) {
            final DSAParams privateParams = ((DSAPrivateKey) privateKey).getParams();
            final DSAParams publicParams = ((DSAPublicKey) publicKey).getParams();
            if (! (privateParams.getG().equals(publicParams.getG()) &&
                   privateParams.getP().equals(publicParams.getP()) &&
                   privateParams.getQ().equals(publicParams.getQ()))) {
                throw new IllegalArgumentException("DSA private/public keys parameters mismatch");
            }

        } else {
            throw new IllegalArgumentException("Unsupported keys algorithm " + algorithm);
        }

        /* Return the algorithm after validation */
        return algorithm;
    }
}
