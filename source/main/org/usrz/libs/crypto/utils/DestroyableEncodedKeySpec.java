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
package org.usrz.libs.crypto.utils;

import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.usrz.libs.utils.Check;

public class DestroyableEncodedKeySpec implements ClosingDestroyable {

    private static final byte[] EMPTY = new byte[0];

    private boolean destroyed;
    private final byte[] encoded;
    private final String format;

    public DestroyableEncodedKeySpec(String format, byte[] encoded) {
        this.format = Check.notNull(format, "Null format");
        this.encoded = Check.notNull(encoded, "Null encoded key");
    }

    public EncodedKeySpec getSpec() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        switch (format) {
            case "PKCS#8":
                return new PKCS8EncodedKeySpec(EMPTY) {
                    @Override public byte[] getEncoded() { return encoded; }
                };
            case "X.509":
                return new X509EncodedKeySpec(EMPTY) {
                    @Override public byte[] getEncoded() { return encoded; }
                };
            default:
                throw new IllegalStateException("Unsupported format " + format);
        }
    }

    @Override
    public void close() {
        try {
            CryptoUtils.destroyArray(encoded);
        } finally {
            destroyed = true;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

}
