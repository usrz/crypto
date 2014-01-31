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

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;

import org.usrz.libs.crypto.utils.PEMException;

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
    throws GeneralSecurityException {
        try {
            final sun.security.util.DerInputStream derInputStream = new sun.security.util.DerInputStream(data);
            final sun.security.util.DerValue[] values = derInputStream.getSequence(0);

            int version = values[0].getInteger();
            if (version != 0) throw new PEMException("Invalid version " + version + " for key");
            if (values.length < 9) throw new PEMException("Invalid number of ASN.1 values for key");

            final BigInteger modulus = values[1].getBigInteger();
            final BigInteger publicExponent = values[2].getBigInteger();
            final BigInteger privateExponent = values[3].getBigInteger();
            final BigInteger prime1 = values[4].getBigInteger();
            final BigInteger prime2 = values[5].getBigInteger();
            final BigInteger exponent1 = values[6].getBigInteger();
            final BigInteger exponent2 = values[7].getBigInteger();
            final BigInteger coefficient = values[8].getBigInteger();

            return (RSAPrivateCrtKey) RSA_KEY_FACTORY.generatePrivate(
                    new RSAPrivateCrtKeySpec(modulus,
                            publicExponent,
                            privateExponent,
                            prime1,
                            prime2,
                            exponent1,
                            exponent2,
                            coefficient));

        } catch (IOException exception) {
            throw new PEMException("Exception parsing ASN.1 format", exception);
        }
    }

}
