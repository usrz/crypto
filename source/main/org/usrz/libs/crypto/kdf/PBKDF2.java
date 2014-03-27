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

import static java.lang.System.arraycopy;
import static org.usrz.libs.crypto.kdf.KDF.Type.PBKDF2;
import static org.usrz.libs.crypto.kdf.KDFSpec.DERIVED_KEY_LENGTH;
import static org.usrz.libs.crypto.kdf.KDFSpec.HASH_FUNCTION;
import static org.usrz.libs.crypto.kdf.KDFSpec.ITERATIONS;

import org.usrz.libs.crypto.hash.HMAC;
import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.utils.configurations.Configurations;
import org.usrz.libs.utils.configurations.ConfigurationsBuilder;

/**
 * The implementation of the Password-Based Key Derivation Function 2.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 * @see <a href="http://en.wikipedia.org/wiki/PBKDF2">Password-Based Key
 *      Derivation Function 2</a>
 */
public class PBKDF2 extends AbstractKDF {

    /* The {@link Hash} to use. */
    private final Hash hash;
    /* The number of iterations to use. */
    private final int iterations;

    /* ====================================================================== */

    /**
     * Create a new {@link PBKDF2} instance wih the specified {@link Hash} and
     * number of iterations.
     * <p>
     * The {@linkplain #getDerivedKeyLength() derived key length} will be
     * the same as the {@linkplain Hash#getHashLength() hash length}.
     */
    public PBKDF2(Hash hash, int iterations) {
        this(hash, iterations, hash == null ? -1 : hash.getHashLength());
    }

    /**
     * Create a new {@link PBKDF2} instance with the specified {@link Hash},
     * number of iterations and derived key length.
     */
    public PBKDF2(Hash hash, int iterations, int derivedKeyLength) {
        this(new KDFSpec(PBKDF2, new ConfigurationsBuilder()
                    .put(DERIVED_KEY_LENGTH, derivedKeyLength)
                    .put(HASH_FUNCTION, hash.name())
                    .put(ITERATIONS, iterations)
                    .build()));
    }

    /**
     * Create a new {@link PBKDF2} from the specified {@link Configurations}
     * or {@link KDFSpec}.
     */
    public PBKDF2(KDFSpec kdfSpec) {
        super(kdfSpec.validateType(PBKDF2));

        hash = kdfSpec.getHash();
        iterations = kdfSpec.requireInteger(ITERATIONS);

        if (iterations < 1) throw new IllegalArgumentException("Iterations must be greater than zero");
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
