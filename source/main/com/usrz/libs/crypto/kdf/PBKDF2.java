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
package com.usrz.libs.crypto.kdf;

import static java.lang.System.arraycopy;

import com.usrz.libs.crypto.hash.HMAC;
import com.usrz.libs.crypto.hash.Hash;

public class PBKDF2 extends AbstractKDF {

    private final Hash hash;
    private final int iterations;
    private final int derivedKeyLength;

    /* ====================================================================== */

    public PBKDF2(Hash hash, int iterations) {
        this(hash, iterations, hash == null ? -1 : hash.getHashLength());
    }

    public PBKDF2(Hash hash, int iterations, int derivedKeyLength) {
        super(derivedKeyLength);

        if (hash == null)
            throw new NullPointerException("Null hash specified");
        if (iterations < 1)
            throw new IllegalArgumentException("Iterations must be greater than zero");
        if (derivedKeyLength < 1)
            throw new IllegalArgumentException("Derived key length must be greater than zero");

        this.hash = hash;
        this.iterations = iterations;
        this.derivedKeyLength = derivedKeyLength;
    }

    public final Hash getHash() {
        return hash;
    }

    public final int getIterations() {
        return iterations;
    }

    /* ====================================================================== */

    @Override
    public void computeKey(byte[] password, byte[] salt, byte[] output, int offset) {

        /* Get a hold on our HMAC instance */
        final HMAC hmac = hash.hmac(password);

        /* Initial calculations */
        final int hmacLength = hmac.getHashLength();
        final int rounds = (int) Math.ceil((double) derivedKeyLength / hmacLength);
        final int r = derivedKeyLength - (rounds - 1) * hmacLength;

        /* Prepare some buffers */
        final byte[] intbuf = new byte[4]; // integer into a byte[]
        final byte[] u = new byte[hmacLength];
        final byte[] t = new byte[hmacLength];

        /* Do our rounds */
        for (int round = 1; round <= rounds; round ++) {
            /* Update our hmac with the salt and round number */
            intbuf[0] = (byte) (round >> 24 & 0xff);
            intbuf[1] = (byte) (round >> 16 & 0xff);
            intbuf[2] = (byte) (round >>  8 & 0xff);
            intbuf[3] = (byte) (round       & 0xff);
            hmac.update(salt).update(intbuf).finish(u, 0);

            /* Save our digest and repeat N iterations */
            arraycopy(u, 0, t, 0, hmacLength);
            for (int iteration = 1; iteration < iterations; iteration++) {
                hmac.update(u).finish(u, 0);
                for (int pos = 0; pos < hmacLength; pos++) t[pos] ^= u[pos];
            }

            arraycopy(t, 0, output, offset + ((round - 1) * hmacLength), (round == rounds ? r : hmacLength));
        }
    }

}
