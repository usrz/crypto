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

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

/**
 * A {@link PEMEntry} for {@linkplain X509Certificate X.509 certificates}.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public final class PEMX509CertificateEntry extends PEMEntry<X509Certificate> {

    PEMX509CertificateEntry(byte[] data, byte[] salt, Encryption encryption) {
        super(Type.X509_CERTIFICATE, data, salt, encryption);
    }

    @Override
    protected X509Certificate doGet(byte[] data)
    throws GeneralSecurityException {
        final ByteArrayInputStream stream = new ByteArrayInputStream(data);
        return ((X509Certificate) CERTIFICATE_FACTORY.generateCertificate(stream));
    }

}
