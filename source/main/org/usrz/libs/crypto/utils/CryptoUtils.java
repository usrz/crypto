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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.security.SecureRandom;
import java.util.Arrays;

public class CryptoUtils {

    private static final SecureRandom random = new SecureRandom();

    private  CryptoUtils() {
        throw new IllegalStateException("Do not construct");
    }

    public static void destroy(char[] array) {
        if (array == null) return;
        for (int x = 0; x < array.length; x ++)
            array[x] = (char) random.nextInt();
        Arrays.fill(array, '\0');
    }

    public static void destroy(byte[] array) {
        if (array == null) return;
        random.nextBytes(array);
        Arrays.fill(array, (byte) 0);
    }

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
            if (destroy) destroy(chars);
            destroy(bytes);
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
            if (destroy) destroy(bytes);
            destroy(chars);
        }
    }
}
