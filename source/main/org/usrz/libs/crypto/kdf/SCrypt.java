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
package org.usrz.libs.crypto.kdf;

import static java.lang.Integer.MAX_VALUE;
import static java.lang.System.arraycopy;

import org.usrz.libs.crypto.hash.Hash;

/**
 * The implementation of <i>Colin Percival</i>'s SCrypt key derivation function.
 * <p>
 * This implementation was <i>heavily based</i> on Will Glozer's own pure-Java
 * <a href="https://github.com/wg/scrypt/">SCrypt</a> implementation,
 * distributed under the terms of the Apache Software License, version 2.
 *
 * @see <a href="https://github.com/wg/scrypt/">Will Glozer's implementation</a>
 * @see <a href="http://en.wikipedia.org/wiki/Scrypt">SCrypt</a>
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class SCrypt extends AbstractKDF {

    /* Our number of iterations (or CPU and memory cost index) */
    private final int iterations;
    /* Our block size */
    private final int blockSize;
    /* Our parallelization factor */
    private final int parallelization;
    /* Remember the number (blockSize * 128). */
    private final int blockSizeTimes128;
    /* The SHA256 KDF for the first hashing (pwd/salt) */
    private final PBKDF2 kdf1;
    /* The SHA256 KDF for the second hashing (final key) */
    private final PBKDF2 kdf2;
    /* Whether to use the native implementation or the Java one */
    private final boolean useNative;

    /**
     * Create a {@link SCrypt} with its specified initialization parameters.
     *
     * @param iterations The CPU and memory cost parameter {@code N}.
     * @param blockSize The block size parameter {@code r}.
     * @param parallelization The parallelization parameter {@code p}.
     * @param derivedKeyLength The length for the derived key.
     */
    public SCrypt(int iterations,
                  int blockSize,
                  int parallelization,
                  int derivedKeyLength) {
        this(new SCryptSpec(iterations,
                            blockSize,
                            parallelization,
                            derivedKeyLength));
    }

    /**
     * Create a new {@link SCrypt} from the specified {@link SCryptSpec}.
     */
    public SCrypt(SCryptSpec kdfSpec) {
        super(kdfSpec);

        /* Store our parameters */
        iterations = kdfSpec.getIterations();
        blockSize = kdfSpec.getBlockSize();
        parallelization = kdfSpec.getParallelization();
        blockSizeTimes128 = blockSize * 128;

        /* Validate parameters */
        if (iterations < 2 || (iterations & (iterations - 1)) != 0)
            throw new IllegalArgumentException("Iterations (CPU/Memory cost) must be a power of 2 greater than 1");
        if (iterations > MAX_VALUE / 128 / blockSize)
            throw new IllegalArgumentException("Iterations (CPU/Memory cost) is too large for given block size");
        if (blockSize > MAX_VALUE / 128 / parallelization)
            throw new IllegalArgumentException("Block size too large for given parallelization");

        /* Check whether we have the native helper available */
        if (useNative = SCryptNativeHelper.isAvailable()) {
            kdf1 = kdf2 = null;
        } else {
            /* Build our PKCS2[SHA256] (or whatever else) instances */
            final Hash hash = kdfSpec.getHash();
            kdf1 = new PBKDF2(hash, 1, parallelization * blockSizeTimes128); // initial pwd/salt
            kdf2 = new PBKDF2(hash, 1, derivedKeyLength); // build final key
        }

    }

    /* ====================================================================== */

    @Override
    protected void computeKey(byte[] password, byte[] salt, byte[] output, int offset) {

        if (useNative) {

            /* Just invoke the native helper */
            SCryptNativeHelper.scrypt(password, salt, output, offset, derivedKeyLength, iterations, blockSize, parallelization);

        } else {

            /* Allocate our buffer */
            final byte[] buffer  = new byte[blockSizeTimes128 * parallelization];

            /* Compute our key */
            kdf1.deriveKey(password, salt, buffer, 0);
            new Computer().compute(buffer);
            kdf2.deriveKey(password, buffer, output, offset);

        }
    }

    /**
     * Return a flag indicating whether native (JNI) processing is enabled.
     */
    boolean isNative() {
        return useNative;
    }

    /**
     * Evaluate (roughly) how much memory will be used to compute the key.
     */
    int getComputationMemoryRequirement() {
        return (blockSizeTimes128 * iterations) // bufferV
             + (blockSizeTimes128 * 2) // buffer1;
             + 192; // buffer2 + bufferCopy + tempBuffer
    }

    /* ====================================================================== */
    /* NOT FOR THE FAINT HEARTED!                                             */
    /* ---------------------------------------------------------------------- */
    /* This inner class is optimized to unprecedented levels of ugliness, and */
    /* should not be as an example on how code is/should/might be written. It */
    /* is beyond ugly and you should not look below this line.                */
    /* ====================================================================== */

    private final class Computer {

        /*
         * Main entry point for computation of a key, the specified array
         * should be initialized properly with a PBKDF2[SHA256] round.
         */
        private void compute(byte[] buffer) {
            for (int i = 0; i < parallelization; i++) {
                scryptROMix(buffer, i * blockSizeTimes128);
            }
        }

        /* ------------------------------------------------------------------ */

        /* Byte buffers required by scryptROMix(...) / scryptBlockMix() */
        private final byte[] bufferV = new byte[blockSizeTimes128 * iterations]; // <- LARGE!!!
        private final byte[] buffer1 = new byte[blockSizeTimes128 * 2];
        private final byte[] buffer2 = new byte[64];

        /* Constant pointer for "integerifycation" */
        private final int intIndex = (2 * blockSize - 1) * 64;

        /* The scryptROMix Algorithm */
        private final void scryptROMix(byte[] buffer, int index) {
            arraycopy(buffer, index, buffer1, 0, blockSizeTimes128);

            for (int i = 0; i < iterations; i++) {
                arraycopy(buffer1, 0, bufferV, i * (blockSizeTimes128), blockSizeTimes128);
                scryptBlockMix();
            }

            for (int i = 0; i < iterations; i++) {
                // inline integerification
                int integerified = ( (buffer1[intIndex    ] & 0xff)
                                   | (buffer1[intIndex + 1] & 0xff) <<  8
                                   | (buffer1[intIndex + 2] & 0xff) << 16
                                   | (buffer1[intIndex + 3] & 0xff) << 24
                                   ) & (iterations - 1);
                blockxor(bufferV, integerified * (blockSizeTimes128), buffer1, 0, blockSizeTimes128);
                scryptBlockMix();
            }

            arraycopy(buffer1, 0, buffer, index, blockSizeTimes128);
        }

        /* ------------------------------------------------------------------ */

        /* The scryptBlockMix Algorithm */
        private final void scryptBlockMix() {

            arraycopy(buffer1, (2 * blockSize - 1) * 64, buffer2, 0, 64);

            for (int i = 0; i < 2 * blockSize; i++) {
                blockxor(buffer1, i * 64, buffer2, 0, 64);
                salsa20_8();
                arraycopy(buffer2, 0, buffer1, blockSizeTimes128 + (i * 64), 64);
            }

            for (int i = 0; i < blockSize; i++) {
                arraycopy(buffer1, blockSizeTimes128 + (i * 2) * 64, buffer1, (i * 64), 64);
            }

            for (int i = 0; i < blockSize; i++) {
                arraycopy(buffer1, blockSizeTimes128 + (i * 2 + 1) * 64, buffer1, (i + blockSize) * 64, 64);
            }
        }

        /* ------------------------------------------------------------------ */

        /* Utility to XOR two byte arrays */
        private final void blockxor(byte[] S, int Si, byte[] D, int Di, int len) {
            for (int i = 0; i < len; i++) {
                D[Di + i] ^= S[Si + i];
            }
        }

        /* ------------------------------------------------------------------ */

        /* Buffers used by salsa20_8() */
        private final int[] bufferCopy = new int[16];
        private final int[] tempBuffer = new int[16];

        /* Apply Salse20_8 core */
        private final void salsa20_8() {

            for (int i = 0, j = 0; i < 16; i++, j += 4) {
                bufferCopy[i]  = (buffer2[j    ] & 0xff) <<  0
                        | (buffer2[j + 1] & 0xff) <<  8
                        | (buffer2[j + 2] & 0xff) << 16
                        | (buffer2[j + 3] & 0xff) << 24;
            }

            arraycopy(bufferCopy, 0, tempBuffer, 0, 16);

            for (int i = 8; i > 0; i -= 2) {
                tempBuffer[ 4] ^= R(tempBuffer[ 0]+tempBuffer[12], 7);  tempBuffer[ 8] ^= R(tempBuffer[ 4]+tempBuffer[ 0], 9);
                tempBuffer[12] ^= R(tempBuffer[ 8]+tempBuffer[ 4],13);  tempBuffer[ 0] ^= R(tempBuffer[12]+tempBuffer[ 8],18);
                tempBuffer[ 9] ^= R(tempBuffer[ 5]+tempBuffer[ 1], 7);  tempBuffer[13] ^= R(tempBuffer[ 9]+tempBuffer[ 5], 9);
                tempBuffer[ 1] ^= R(tempBuffer[13]+tempBuffer[ 9],13);  tempBuffer[ 5] ^= R(tempBuffer[ 1]+tempBuffer[13],18);
                tempBuffer[14] ^= R(tempBuffer[10]+tempBuffer[ 6], 7);  tempBuffer[ 2] ^= R(tempBuffer[14]+tempBuffer[10], 9);
                tempBuffer[ 6] ^= R(tempBuffer[ 2]+tempBuffer[14],13);  tempBuffer[10] ^= R(tempBuffer[ 6]+tempBuffer[ 2],18);
                tempBuffer[ 3] ^= R(tempBuffer[15]+tempBuffer[11], 7);  tempBuffer[ 7] ^= R(tempBuffer[ 3]+tempBuffer[15], 9);
                tempBuffer[11] ^= R(tempBuffer[ 7]+tempBuffer[ 3],13);  tempBuffer[15] ^= R(tempBuffer[11]+tempBuffer[ 7],18);
                tempBuffer[ 1] ^= R(tempBuffer[ 0]+tempBuffer[ 3], 7);  tempBuffer[ 2] ^= R(tempBuffer[ 1]+tempBuffer[ 0], 9);
                tempBuffer[ 3] ^= R(tempBuffer[ 2]+tempBuffer[ 1],13);  tempBuffer[ 0] ^= R(tempBuffer[ 3]+tempBuffer[ 2],18);
                tempBuffer[ 6] ^= R(tempBuffer[ 5]+tempBuffer[ 4], 7);  tempBuffer[ 7] ^= R(tempBuffer[ 6]+tempBuffer[ 5], 9);
                tempBuffer[ 4] ^= R(tempBuffer[ 7]+tempBuffer[ 6],13);  tempBuffer[ 5] ^= R(tempBuffer[ 4]+tempBuffer[ 7],18);
                tempBuffer[11] ^= R(tempBuffer[10]+tempBuffer[ 9], 7);  tempBuffer[ 8] ^= R(tempBuffer[11]+tempBuffer[10], 9);
                tempBuffer[ 9] ^= R(tempBuffer[ 8]+tempBuffer[11],13);  tempBuffer[10] ^= R(tempBuffer[ 9]+tempBuffer[ 8],18);
                tempBuffer[12] ^= R(tempBuffer[15]+tempBuffer[14], 7);  tempBuffer[13] ^= R(tempBuffer[12]+tempBuffer[15], 9);
                tempBuffer[14] ^= R(tempBuffer[13]+tempBuffer[12],13);  tempBuffer[15] ^= R(tempBuffer[14]+tempBuffer[13],18);
            }

            for (int i = 0; i < 16; ++i) bufferCopy[i] = tempBuffer[i] + bufferCopy[i];

            for (int i = 0, j = 0; i < 16; i++, j += 4) {
                buffer2[j    ] = (byte) (bufferCopy[i] >> 0  & 0xff);
                buffer2[j + 1] = (byte) (bufferCopy[i] >> 8  & 0xff);
                buffer2[j + 2] = (byte) (bufferCopy[i] >> 16 & 0xff);
                buffer2[j + 3] = (byte) (bufferCopy[i] >> 24 & 0xff);
            }
        }

        /* Rotate bits in an integer */
        private final int R(int a, int b) {
            return (a << b) | (a >>> (32 - b));
        }
    }
}
