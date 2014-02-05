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
package org.usrz.libs.crypto.cert;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class KeyPairBuilder {

    private String algorithm = "RSA";
    private int keySize = 1024;

    public KeyPairBuilder() {
        /* Nothing to do, initialized to sensible defaults */
    }

    public KeyPair build() {
        final KeyPairGenerator generator;
        try {
            generator = KeyPairGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Algoritmh \"" + algorithm + "\" not supported", exception);
        }
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public KeyPairBuilder algorithm(String algorithm) {
        if (algorithm == null) throw new NullPointerException("Null algorithm");
        this.algorithm = algorithm;
        return this;
    }

    public KeyPairBuilder keySize(int keySize) {
        if (keySize < 0) throw new IllegalArgumentException("Invalid key size " + keySize);
        this.keySize = keySize;
        return this;
    }
}
