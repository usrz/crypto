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
package org.usrz.libs.crypto.codecs;

import java.util.Arrays;

/**
 * A {@link Codec} implementing the Base 32 encoding algorithm <b>without
 * padding</b>.
 *
 * Regardless of the case specified at
 * {@linkplain #Base32Codec(boolean) construction} this class will always decode
 * {@link String}s using all possible alphabets.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Base32">Base 32</a>
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class Base32Codec extends AbstractCodec {

    private static final char[] BASE32_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final char[] BASE32_LOWER = "abcdefghijklmnopqrstuvwxyz234567".toCharArray();
    private static final int[] BASE32_VALUES = new int[128];

    static {
        Arrays.fill(BASE32_VALUES, -1);
        for (int x = 0; x < BASE32_UPPER.length; x++) BASE32_VALUES[BASE32_UPPER[x]] = x;
        for (int x = 0; x < BASE32_LOWER.length; x++) BASE32_VALUES[BASE32_LOWER[x]] = x;
    }

    /* ====================================================================== */

    /* The alphabet (upper or lower case) to use for encoding */
    private final char[] alphabet;

    /**
     * Create a new {@link HexCodec} using the default upper-case alphabet.
     */
    public Base32Codec() {
        alphabet = BASE32_UPPER;
    }

    /**
     * Create a new {@link HexCodec} using the default upper-case alphabet.
     */
    public Base32Codec(final boolean upperCase) {
        alphabet = upperCase ? BASE32_UPPER : BASE32_LOWER;
    }

    /* ====================================================================== */

    @Override
    public byte[] decode(String data)
    throws IllegalArgumentException {

        int i, index, offset, digit;
        byte[] bytes = new byte[data.length() * 5 / 8];

        for (i = 0, index = 0, offset = 0; i < data.length(); i++) {
            final char c = data.charAt(i);

            if (c >= BASE32_VALUES.length) {
                throw new IllegalArgumentException("Invalid character '" + data.charAt(i)
                                           + "' at offset " + i + " in \"" + data + "\"");
            }

            digit = BASE32_VALUES[data.charAt(i)];

            if (digit < 0) {
                throw new IllegalArgumentException("Invalid character '" + data.charAt(i)
                                           + "' at offset " + i + " in \"" + data + "\"");
            }

            if (index <= 3) {
                index = (index + 5) % 8;
                if (index == 0) {
                    bytes[offset] |= digit;
                    offset++;
                    if (offset >= bytes.length)
                        break;
                } else {
                    bytes[offset] |= digit << (8 - index);
                }
            } else {
                index = (index + 5) % 8;
                bytes[offset] |= (digit >>> index);
                offset++;

                if (offset >= bytes.length) {
                    break;
                }
                bytes[offset] |= digit << (8 - index);
            }
        }
        return bytes;
    }

    @Override
    public String encode(byte[] data, int offset, int length) {
        int i = offset, index = 0, digit = 0, end = offset + length;
        int currByte, nextByte;
        StringBuilder base32 = new StringBuilder((length + 7) * 8 / 5);

        while (i < end) {
            currByte = (data[i] >= 0) ? data[i] : (data[i] + 256);

            /* Is the current digit going to span a byte boundary? */
            if (index > 3) {
                if ((i + 1) < end) {
                    nextByte = (data[i + 1] >= 0)
                       ? data[i + 1] : (data[i + 1] + 256);
                } else {
                    nextByte = 0;
                }

                digit = currByte & (0xFF >> index);
                index = (index + 5) % 8;
                digit <<= index;
                digit |= nextByte >> (8 - index);
                i++;
            } else {
                digit = (currByte >> (8 - (index + 5))) & 0x1F;
                index = (index + 5) % 8;
                if (index == 0)
                    i++;
            }
            base32.append(alphabet[digit]);
        }

        return base32.toString();
    }

}
