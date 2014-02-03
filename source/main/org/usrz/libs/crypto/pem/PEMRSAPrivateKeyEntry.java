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

import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

/**
 * A {@link PEMEntry} for {@linkplain RSAPrivateCrtKey RSA private keys}.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public final class PEMRSAPrivateKeyEntry extends PEMEntry<RSAPrivateCrtKey> {

    PEMRSAPrivateKeyEntry(byte[] data, byte[] salt, Encryption encryption) {
        super(Type.RSA_PRIVATE_KEY, data, salt, encryption);
    }

    @Override
    protected RSAPrivateCrtKey doGet(byte[] data)
    throws PEMException, InvalidKeySpecException {
        final RSAPrivateKey privateKey = RSAPrivateKey.getInstance(data);
        return (RSAPrivateCrtKey) RSA_KEY_FACTORY.generatePrivate(
                new RSAPrivateCrtKeySpec(privateKey.getModulus(),
                                         privateKey.getPublicExponent(),
                                         privateKey.getPrivateExponent(),
                                         privateKey.getPrime1(),
                                         privateKey.getPrime2(),
                                         privateKey.getExponent1(),
                                         privateKey.getExponent2(),
                                         privateKey.getCoefficient()));
    }

}
