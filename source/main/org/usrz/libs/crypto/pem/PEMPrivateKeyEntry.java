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
package org.usrz.libs.crypto.pem;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.openssl.PEMKeyPair;

public final class PEMPrivateKeyEntry extends PEMEntry<KeyPair> {

    private final KeyPair keyPair;

    PEMPrivateKeyEntry(PEMKeyPair key)
    throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException {
        super(KeyPair.class, false);
        final PEMFactory factory = new PEMFactory();
        keyPair = new KeyPair(factory.getPublicKey(key.getPublicKeyInfo()),
                              factory.getPrivateKey(key.getPrivateKeyInfo()));
    }

    @Override
    public KeyPair get() {
        return keyPair;
    }

}
