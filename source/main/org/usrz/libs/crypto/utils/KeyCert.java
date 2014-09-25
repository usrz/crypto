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

import static org.usrz.libs.utils.Check.notNull;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

public class KeyCert { // KeyPair is final :-(

    private final PrivateKey privateKey;
    private final Certificate certificate;

    public KeyCert(Certificate certificate, PrivateKey privateKey) {
        this.privateKey = notNull(privateKey, "Null private key");
        this.certificate = notNull(certificate, "Null certificate");
    }

    public PublicKey getPublic() {
        return certificate.getPublicKey();
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public PrivateKey getPrivate() {
        return privateKey;
    }

}
