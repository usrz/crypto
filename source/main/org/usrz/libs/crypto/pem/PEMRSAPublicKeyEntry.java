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

import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

/**
 * A {@link PEMEntry} for {@linkplain RSAPublicKey RSA public keys}.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public final class PEMRSAPublicKeyEntry extends PEMEntry<RSAPublicKey> {

    PEMRSAPublicKeyEntry(byte[] data, byte[] salt, Encryption encryption) {
        super(Type.RSA_PUBLIC_KEY, data, salt, encryption);
    }

    @Override
    protected RSAPublicKey doGet(byte[] data)
    throws InvalidKeySpecException {
        return (RSAPublicKey) RSA_KEY_FACTORY.generatePublic(new X509EncodedKeySpec(data));
    }

}
