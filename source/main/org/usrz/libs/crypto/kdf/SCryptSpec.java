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

import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.crypto.kdf.KDF.Function;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * A {@link KDFSpec} for the {@link SCrypt} KDF.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
@JsonPropertyOrder({"function","hash","derivedKeyLength","iterations","blockSize","parallelization"})
public class SCryptSpec extends AbstractKDFSpec {

    private final int iterations;
    private final int blockSize;
    private final int parallelization;

    public SCryptSpec(int iterations,
                      int blockSize,
                      int parallelization) {
        this(null, 0, iterations, blockSize, parallelization);
    }

    public SCryptSpec(int iterations,
                      int blockSize,
                      int parallelization,
                      int derivedKeyLength) {
        this(null, derivedKeyLength, iterations, blockSize, parallelization);
    }

    public SCryptSpec(Hash hash,
                      int derivedKeyLength,
                      int iterations,
                      int blockSize,
                      int parallelization) {
        super(Function.SCRYPT, hash, derivedKeyLength);

        /* Defaults */
        if (blockSize < 1) blockSize = 8;
        if (parallelization < 1) parallelization = 1;

        /* Validate parameters */
        if (iterations < 2 || (iterations & (iterations - 1)) != 0)
            throw new IllegalArgumentException("Iterations (CPU/Memory cost) must be a power of 2 greater than 1");
        if (iterations > MAX_VALUE / 128 / blockSize)
            throw new IllegalArgumentException("Iterations (CPU/Memory cost) is too large for given block size");
        if (blockSize > MAX_VALUE / 128 / parallelization)
            throw new IllegalArgumentException("Block size too large for given parallelization");

        /* Store parameters */
        this.iterations = iterations;
        this.blockSize = blockSize;
        this.parallelization = parallelization;
    }

    public final int getIterations() {
        return iterations;
    }

    public final int getBlockSize() {
        return blockSize;
    }

    public final int getParallelization() {
        return parallelization;
    }

    @Override
    public int hashCode() {
        int h = (31 * super.hashCode()) + iterations;
        h = (31 * h) + blockSize;
        h = (31 * h) + parallelization;
        return h;
    }

    @Override
    public boolean equals(Object object) {
        if (super.equals(object)) try {
            final SCryptSpec spec = (SCryptSpec) object;
            return iterations == spec.iterations
                && blockSize == spec.blockSize
                && parallelization == spec.parallelization;
        } catch (ClassCastException exception) {
            /* Ignore */
        }
        return false;
    }
}
