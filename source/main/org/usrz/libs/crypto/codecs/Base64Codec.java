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

/**
 * A relatively-fast {@link Codec} implementing the Base 64 encoding algorithm.
 *
 * Regardless of the {@link Base64Codec.Alphabet Alphabet} specified at
 * {@linkplain #Base64Codec(Alphabet) construction} (and because the various
 * alphabets do not overlap) this class will always decode {@link String}s
 * using all possible alphabets.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Base64">Base 64</a>
 */
public class Base64Codec extends AbstractCodec {

    /**
     * The various encoding alphabets supported by the {@link Base64Codec}.
     */
    public enum Alphabet {
        /**
         * Standard alphabet, as specified by
         * <a href="http://tools.ietf.org/html/rfc4648#section-5">RFC-4648,
         * Section 5</a>.
         */
        STANDARD("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),

        /**
         * "Modular Crypt" format, as referenced (but not specified) by
         * <a href="http://packages.python.org/passlib/modular_crypt_format.html">Python's
         * PassLib</a> and used in their
         * <a href="http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html">Generic
         * PBKDF2 Hashes</a> implementation.
         */

        MODULAR_CRYPT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./"),
        /**
         * URL and file safe alphabet, as specified by
         * <a href="http://tools.ietf.org/html/rfc4648#section-5">RFC-4648,
         * Section 5</a>.
         */
        URL_SAFE("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

        private char[] alphabet;

        private Alphabet(final String alphabetString) {
            alphabet = alphabetString.toCharArray();
        }
    }

    /* ====================================================================== */

    private static final int[] VALUES;

    static {
        VALUES = new int[128];
        for (int x = 0; x < VALUES.length; x++) VALUES[x] = -1;
        for (Alphabet alphabet: Alphabet.values())
            for (int x = 0; x < alphabet.alphabet.length; x++)
                VALUES[alphabet.alphabet[x]] = x;
    }

    /* ====================================================================== */

    /** The current alphabet used for encoding. */
    private final char[] alphabet;
    /** Whether we support padding or not. */
    private final boolean padding;

    /**
     * Create a new {@link Base64Codec} using the
     * {@link Base64Codec.Alphabet#STANDARD STANDARD} encoding alphabet.
     */
    public Base64Codec() {
        this(Alphabet.STANDARD, true);
    }

    /**
     * Create a new {@link Base64Codec} using the specified {@link Alphabet}.
     */
    public Base64Codec(final Alphabet alphabet) {
        this(alphabet, true);
    }

    /**
     * Create a new {@link Base64Codec} using the
     * {@link Base64Codec.Alphabet#STANDARD STANDARD} encoding alphabet.
     */
    public Base64Codec(final boolean padding) {
        this(Alphabet.STANDARD, padding);
    }

    /**
     * Create a new {@link Base64Codec} using the specified {@link Alphabet}.
     */
    public Base64Codec(final Alphabet alphabet, final boolean padding) {
        this.alphabet = alphabet.alphabet;
        this.padding = padding;
    }
    /* ====================================================================== */

    @Override
    public String encode(final byte[] data, final int offset, final int length) {

        /* Shortcut */
        if (length == 0) return EMPTY_STRING;

        /* How many bytes will be "left" after the main encoding loop */
        final int leftovers = length % 3;

        /* How many characters we need to store the bytes minus leftovers */
        final int fullchars = (length / 3) * 4;

        /* Current position */
        int position = offset;

        /*
         * The final character array's length will be either full characters
         * (if the bytes are multple of 3) or the full characters plus two or
         * three depending whether we have 1 or 2 bytes left to encode.
         * As we're in a switch statement, also calculate the last few chars.
         */
        final char[] result;
        switch (leftovers) {
            case 1:
                result = new char[fullchars + (padding ? 4 : 2)];
                result[fullchars    ] = alphabet[(data[position + length - 1] >> 2) & 0x03f];
                result[fullchars + 1] = alphabet[(data[position + length - 1] << 4) & 0x030];
                if (padding) {
                    result[fullchars + 2] = '=';
                    result[fullchars + 3] = '=';
                }
                break;
            case 2:
                result = new char[fullchars + (padding ? 4 : 3)];
                result[fullchars    ] = alphabet[ (data[position + length - 2] >> 2) & 0x03f];
                result[fullchars + 1] = alphabet[((data[position + length - 2] << 4) & 0x030) |
                                                 ((data[position + length - 1] >> 4) & 0x00f)];
                result[fullchars + 2] = alphabet[ (data[position + length - 1] << 2) & 0x03c];
                if (padding) result[fullchars + 3] = '=';
                break;
            default:
                result = new char[fullchars];
        }

        /*
         * Start the main loop, encoding all bytes in groups of 3, each chunk
         * producing four characters.
         */
        int resultpos = 0;
        while (resultpos < fullchars) {
            result[resultpos++] = alphabet[ (data[position]   >> 2) & 0x03f];
            result[resultpos++] = alphabet[((data[position++] << 4) & 0x030) |
                                           ((data[position]   >> 4) & 0x00f)];
            result[resultpos++] = alphabet[((data[position++] << 2) & 0x03c) |
                                           ((data[position]   >> 6) & 0x003)];
            result[resultpos++] = alphabet[  data[position++]       & 0x03f];
        }

        /* All done */
        return new String(result);
    }

    @Override
    public byte[] decode(String source) {

        /* Shortcut */
        if (source.length() == 0) return EMPTY_ARRAY;

        /* Trim the end padding */
        while (source.charAt(source.length() - 1) == '=')
            source = source.substring(0, source.length() - 1);

        /* Retrieve the array of characters of the source string. */
        final char[] characters = source.toCharArray();

        /* Figure out how many full chunks of three bytes we can decode */
        final int fullbytes = (characters.length / 4) * 3;

        /* Figure out how many characters are left over to decode */
        final int leftovers = characters.length % 4;

        /* Allocate some space for the decoded string */
        final byte[] result;
        switch (leftovers) {
            case 0:
                result = new byte[fullbytes];
                break;
            case 2:
                result = new byte[fullbytes + 1];
                result[fullbytes] = (byte) (((VALUES[characters[characters.length - 2]] << 2) & 0x0fc) |
                                            ((VALUES[characters[characters.length - 1]] >> 4) & 0x003));
                break;
            case 3:
                result = new byte[fullbytes + 2];
                result[fullbytes    ] = (byte) (((VALUES[characters[characters.length - 3]] << 2) & 0x0fc) |
                                                ((VALUES[characters[characters.length - 2]] >> 4) & 0x003));
                result[fullbytes + 1] = (byte) (((VALUES[characters[characters.length - 2]] << 4) & 0x0f0) |
                                                ((VALUES[characters[characters.length - 1]] >> 2) & 0x00f));
                break;
            default:
                throw new IllegalArgumentException("Invalid input length");
        }

        int resultpos = 0;
        int datapos = 0;
        try {
            while (resultpos < fullbytes) {
                int v1 = VALUES[characters[datapos++]];
                int v2 = VALUES[characters[datapos++]];
                int v3 = VALUES[characters[datapos++]];
                int v4 = VALUES[characters[datapos++]];
                if ((v1 < 0) || (v2 < 0) || (v3 < 0) || (v4 < 0)) {
                    throw new IllegalArgumentException("Invalid character in input");
                }
                result[resultpos++] = (byte) (((v1 << 2) & 0x0fc) | ((v2 >> 4) & 0x003));
                result[resultpos++] = (byte) (((v2 << 4) & 0x0f0) | ((v3 >> 2) & 0x00f));
                result[resultpos++] = (byte) (((v3 << 6) & 0x0c0) | ((v4     ) & 0x03f));
            }
        } catch (ArrayIndexOutOfBoundsException exception) {
            throw new IllegalArgumentException("Invalid character in input", exception);
        }

        return result;
    }
}
