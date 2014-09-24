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

import static org.usrz.libs.crypto.kdf.KDF.Function.PBKDF2;

import org.usrz.libs.crypto.hash.Hash;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * A {@link KDFSpec} for the {@link PBKDF2} KDF.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
@JsonPropertyOrder({"function","hash","derivedKeyLength","iterations"})
public class PBKDF2Spec extends AbstractKDFSpec {

    private final int iterations;

    public PBKDF2Spec(int iterations) {
        this(null, 0, iterations);
    }

    public PBKDF2Spec(Hash hash, int derivedKeyLength, int iterations) {
        super(PBKDF2, hash, derivedKeyLength);
        if (iterations < 1) throw new IllegalArgumentException("Invalid number of iterations " + iterations);
        this.iterations = iterations;
    }

    public final int getIterations() {
        return iterations;
    }

    @Override
    public int hashCode() {
        return (31 * super.hashCode()) + iterations;
    }

    @Override
    public boolean equals(Object object) {
        if (super.equals(object)) try {
            final PBKDF2Spec spec = (PBKDF2Spec) object;
            return getIterations() == spec.getIterations();
        } catch (ClassCastException exception) {
            /* Ignore */
        }
        return false;
    }

}
