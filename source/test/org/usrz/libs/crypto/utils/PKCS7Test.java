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

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.testng.annotations.Test;
import org.usrz.libs.crypto.pem.PEMEntry;
import org.usrz.libs.crypto.pem.PEMReader;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.testing.Exec;
import org.usrz.libs.testing.IO;

public class PKCS7Test extends AbstractTest {

    @Test
    public void testSignature()
    throws Exception {
        final PEMReader keyReader = new PEMReader(IO.resource("key.pem"));
        final RSAPrivateKey key = (RSAPrivateKey) ((KeyPair)keyReader.read().get()).getPrivate();
        keyReader.close();

        final List<X509Certificate> certificates = new ArrayList<>();
        final PEMReader certificatesReader = new PEMReader(IO.resource("cert.pem"));
        PEMEntry<?> entry = null;
        while ((entry = certificatesReader.read()) != null) {
            certificates.add((X509Certificate) entry.get());
        }
        certificatesReader.close();

        final byte[] data = new byte[65536];
        new Random().nextBytes(data);

        final byte[] signature = PKCS7.sign(key, certificates.get(0), null, data);

        final File certFile = IO.copyTempFile("cert.pem", "cert", "pem");
        final File contentFile = IO.copyTempFile(data, "data", "bin");
        final File signatureFile = IO.copyTempFile(signature, "data", "bin");

        final Process process = Exec.exec(new String[] {
                "openssl", "smime", "-verify", "-binary", "-noverify",
                "-inform", "DER",
                "-out", "/dev/null",
                "-signer", certFile.getAbsolutePath(),
                "-content", contentFile.getAbsolutePath(),
                "-in", signatureFile.getAbsolutePath()
        });

        assertEquals(process.waitFor(), 0, "OpenSSL failure");
    }
}
