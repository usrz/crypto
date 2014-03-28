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
import org.usrz.libs.crypto.kdf.KDF.Type;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * A {@link KDFSpec} for the {@link SCrypt} KDF.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
@JsonPropertyOrder({"type","hash","derivedKeyLength","cpuMemoryCost","blockSize","parallelization"})
public class SCryptSpec extends AbstractKDFSpec {

    private final int cpuMemoryCost;
    private final int blockSize;
    private final int parallelization;

    public SCryptSpec(int cpuMemoryCost,
                      int blockSize,
                      int parallelization) {
        this(null, 0, cpuMemoryCost, blockSize, parallelization);
    }

    public SCryptSpec(int cpuMemoryCost,
                      int blockSize,
                      int parallelization,
                      int derivedKeyLength) {
        this(null, derivedKeyLength, cpuMemoryCost, blockSize, parallelization);
    }

    public SCryptSpec(Hash hash,
                      int derivedKeyLength,
                      int cpuMemoryCost,
                      int blockSize,
                      int parallelization) {
        super(Type.SCRYPT, hash, derivedKeyLength);

        /* Validate parameters */
        if (cpuMemoryCost < 2 || (cpuMemoryCost & (cpuMemoryCost - 1)) != 0)
            throw new IllegalArgumentException("CPU/Memory cost must be a power of 2 greater than 1");
        if (cpuMemoryCost > MAX_VALUE / 128 / blockSize)
            throw new IllegalArgumentException("Parameter CPU/Memory cost is too large for given block size");
        if (blockSize > MAX_VALUE / 128 / parallelization)
            throw new IllegalArgumentException("Block size too large for given parallelization");

        /* Store parameters */
        this.cpuMemoryCost = cpuMemoryCost;
        this.blockSize = blockSize;
        this.parallelization = parallelization;
    }

    public final int getCpuMemoryCost() {
        return cpuMemoryCost;
    }

    public final int getBlockSize() {
        return blockSize;
    }

    public final int getParallelization() {
        return parallelization;
    }

    @Override
    public int hashCode() {
        return (super.hashCode() ^ ((blockSize << 16) ^ parallelization)) * cpuMemoryCost;
    }

    @Override
    public boolean equals(Object object) {
        if (super.equals(object)) try {
            final SCryptSpec spec = (SCryptSpec) object;
            return cpuMemoryCost == spec.cpuMemoryCost
                && blockSize == spec.blockSize
                && parallelization == spec.parallelization;
        } catch (ClassCastException exception) {
            /* Ignore */
        }
        return false;
    }
}
