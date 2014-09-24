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

import org.usrz.libs.utils.Check;

/**
 * An abstract implementation of the {@link KDF} interface.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public abstract class AbstractKDF implements KDF {

    /** The derived key length to return. */
    protected final int derivedKeyLength;
    /** The {@link KDFSpec} associated with this instance. */
    protected final KDFSpec kdfSpec;

    /**
     * Create a new {@link AbstractKDF} instance.
     */
    public AbstractKDF(KDFSpec kdfSpec) {
        this.kdfSpec = Check.notNull(kdfSpec, "Null spec");

        derivedKeyLength = kdfSpec.getDerivedKeyLength();
        if (derivedKeyLength < 1)
            throw new IllegalArgumentException("Derived key length less than zero");
    }

    @Override
    public final KDFSpec getKDFSpec() {
        return kdfSpec;
    }

    @Override
    public final byte[] deriveKey(byte[] password, byte[] salt) {

        /* Check for null parameters */
        if (password == null) throw new NullPointerException("Null password");
        if (salt == null) throw new NullPointerException("Null salt");

        /* Create an output buffer and compute */
        final byte[] result = new byte[derivedKeyLength];
        computeKey(password, salt, result, 0);
        return result;
    }

    @Override
    public final void deriveKey(byte[] password, byte[] salt, byte[] output, int offset) {

        /* Check for null parameters */
        if (password == null) throw new NullPointerException("Null password");
        if (salt == null) throw new NullPointerException("Null salt");
        if (output == null) throw new NullPointerException("Null output");

        /* Check offsets and length for output */
        if (offset < 0) throw new IllegalArgumentException("Negative offset");
        if (output.length < offset + derivedKeyLength)
            throw new IllegalArgumentException("Buffer too short");

        /* Perform the actual computation */
        computeKey(password, salt, output, offset);

    }

    /**
     * Method to be implemented by concrete classes to actually compute the
     * derived key after parameters have been checked.
     */
    protected abstract void computeKey(byte[] password, byte[] salt, byte[] output, int offset);

}
