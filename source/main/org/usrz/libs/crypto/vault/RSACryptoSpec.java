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
package org.usrz.libs.crypto.vault;

import static org.usrz.libs.crypto.vault.Crypto.Algorithm.RSA;

import org.usrz.libs.crypto.vault.Crypto.Algorithm;

public class RSACryptoSpec implements CryptoSpec {

    public RSACryptoSpec() {
        /* Nothing to do here... */
    }

    @Override
    public Algorithm getAlgorithm() {
        return RSA;
    }

    /* ====================================================================== */

    @Override
    public boolean equals(Object object) {
        if (object == null) return false;
        if (object == this) return true;
        try {
            final RSACryptoSpec spec = (RSACryptoSpec) object;
            return getAlgorithm().equals(spec.getAlgorithm());
        } catch (ClassCastException exception) {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return getAlgorithm().hashCode();
    }

}
