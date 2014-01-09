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

public abstract class AbstractKDF implements KDF {

    private final int derivedKeyLength;

    public AbstractKDF(int derivedKeyLength) {
        if (derivedKeyLength < 1)
            throw new IllegalArgumentException("Derived key length less than zero");
        this.derivedKeyLength = derivedKeyLength;
    }

    @Override
    public final int getDerivedKeyLength() {
        return derivedKeyLength;
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
    public void deriveKey(byte[] password, byte[] salt, byte[] output, int offset) {

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

    protected abstract void computeKey(byte[] password, byte[] salt, byte[] output, int offset);

}
