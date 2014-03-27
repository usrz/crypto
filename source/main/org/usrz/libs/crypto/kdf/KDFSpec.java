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

import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;

import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.crypto.kdf.KDF.Type;
import org.usrz.libs.utils.configurations.Configurations;
import org.usrz.libs.utils.configurations.ConfigurationsBuilder;

/**
 * A simple {@link Configurations} extension defining the operating
 * specifications of a generic {@link KDF}.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class KDFSpec extends Configurations {

    /** The <em>algorithm</em> of this KDF. */
    public static final String ALGORITHM = "algorithm";
    /** The <em>derived key length</em> of this KDF. */
    public static final String DERIVED_KEY_LENGTH = "derivedKeyLength";
    /** The <em>hash function</em> of this KDF. */
    public static final String HASH_FUNCTION = "hashFunction";
    /** The <em>number of iterations</em> of this KDF. */
    public static final String ITERATIONS = "iterations";
    /** The <em>cpu/memory cost</em> of this KDF. */
    public static final String CPU_MEMORY_COST = "cpuMemoryCost";
    /** The <em>block size</em> of this KDF. */
    public static final String BLOCK_SIZE = "blockSize";
    /** The <em>parallelization</em> of this KDF. */
    public static final String PARALLELIZATION = "parallelization";

    /* ====================================================================== */

    /* Our {@link Configurations} backing this instance. */
    private final Configurations configurations;
    /* The {@link Type} of the {@link KDF} */
    private final Type type;

    /**
     * Create a new {@link KDFSpec} out of a {@link Configurations} object.
     */
    public KDFSpec(Configurations configurations) {
        final String algorithm = configurations.requireString(ALGORITHM);
        try {
            type = Type.valueOf(algorithm.toUpperCase());
        } catch (IllegalArgumentException exception) {
            throw new NoSuchElementException("Unsupported KDF algorithm " + algorithm);
        }
        this.configurations = configurations;
    }

    /**
     * Create a new {@link KDFSpec} out of a {@link Configurations} object with
     * default details for the specified {@link Type}.
     */
    public KDFSpec(Type defaultAlgorithm, Configurations configurations) {
        this(configurations.merge(new ConfigurationsBuilder()
                   .put(ALGORITHM, Objects.requireNonNull(defaultAlgorithm, "Null algorithm").name())
                   .put(HASH_FUNCTION, Objects.requireNonNull(defaultAlgorithm.getDefaultHash(), "Null hash").name())
                   .put(DERIVED_KEY_LENGTH, defaultAlgorithm.getDefaultHash().getHashLength())
                   .build()));
    }

    /* ====================================================================== */

    /* Validate the type */
    final KDFSpec validateType(Type type) {
        if (this.type == type) return this;
        throw new IllegalStateException("Invalid type " + this.type + ", required " + type);
    }

    /* ====================================================================== */

    /**
     * Return the {@link Type} associated with this {@link KDFSpec}.
     */
    public final Type getType() {
        return type;
    }

    /**
     * Return the {@link Hash} associated with this {@link KDFSpec}.
     */
    public final Hash getHash() {
        final String hash = this.getString(HASH_FUNCTION);
        try {
            if (hash != null) return Hash.valueOf(hash.toUpperCase());
            return getType().getDefaultHash();
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Invalid hash function " + hash);
        }
    }

    /* ====================================================================== */

    @Override
    public final String getString(Object key, String defaultValue) {
        return configurations.getString(key, defaultValue);
    }

    @Override
    public final Set<Entry<String, String>> entrySet() {
        return configurations.entrySet();
    }

    @Override
    public final int size() {
        return configurations.size();
    }

}
