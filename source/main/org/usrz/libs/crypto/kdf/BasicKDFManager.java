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

/**
 * A basic implementation of a {@link KDFManager} creating instances when
 * required.
 */
public class BasicKDFManager implements KDFManager {

    /**
     * Create a {@link BasicKDFManager} instance.
     */
    public BasicKDFManager() {
        /* Nothing to do */
    }

    @Override
    public KDF getKDF(KDFSpec spec) {
        switch (spec.getFunction()) {
            case OPENSSL: return new OpenSSLKDF((OpenSSLKDFSpec) spec);
            case PBKDF2:  return new PBKDF2((PBKDF2Spec) spec);
            case SCRYPT:  return new SCrypt((SCryptSpec) spec);
        }
        throw new UnsupportedOperationException("Invalid KDF function " + spec.getFunction());
    }
}
