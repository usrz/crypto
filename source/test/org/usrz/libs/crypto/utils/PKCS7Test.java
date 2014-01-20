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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Random;

import org.testng.Assert;
import org.testng.annotations.Test;

public class PKCS7Test {

    @Test
    public void testSignature()
    throws Exception {
        final RSAPrivateKey key = PEM.loadPrivateKey(getClass().getResource("key.pem"));
        final List<X509Certificate> certificates = PEM.loadCertificates(getClass().getResource("cert.pem"));

        final byte[] data = new byte[65536];
        new Random().nextBytes(data);

        final byte[] signature = PKCS7.sign(key, certificates.get(0), null, data);

        final File certFile = copyFile(getClass().getResource("cert.pem"), "cert", "pem");
        final File contentFile = copyFile(data, "data", "bin");
        final File signatureFile = copyFile(signature, "data", "bin");

        final String[] commandLine = {
                "openssl", "smime", "-verify", "-binary", "-noverify",
                "-inform", "DER",
                "-out", "/dev/null",
                "-signer", certFile.getAbsolutePath(),
                "-content", contentFile.getAbsolutePath(),
                "-in", signatureFile.getAbsolutePath()
        };

        System.err.print("[calling]: =>");
        for (String string: commandLine) {
            System.err.print(' ');
            System.err.print(string);
        }
        System.err.println();

        final Process process = Runtime.getRuntime().exec(commandLine);

        new Thread(new Copier(process.getInputStream(), System.out)).start();
        new Thread(new Copier(process.getErrorStream(), System.err)).start();

        Assert.assertEquals(process.waitFor(), 0, "OpenSSL failure");
    }

    private final File copyFile(URL url, String prefix, String suffix)
    throws IOException {
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        final InputStream input = url.openStream();

        final byte[] buffer = new byte[65536];

        int length = -1;
        while ((length = input.read(buffer)) >= 0) {
            if (length > 0) data.write(buffer, 0, length);
        }

        return copyFile(data.toByteArray(), prefix, suffix);
    }

    private final File copyFile(byte[] data, String prefix, String suffix)
    throws IOException {
        final File file = File.createTempFile(prefix + "-", "." +suffix);
        file.deleteOnExit();

        final OutputStream output = new FileOutputStream(file);
        output.write(data);
        output.flush();
        output.close();

        return file;
    }

    private final class Copier implements Runnable {

        private final InputStream input;
        private final OutputStream output;

        private Copier(InputStream input, OutputStream output) {
            this.input = input;
            this.output = output;
        }

        @Override
        public void run() {
            final byte[] buffer = new byte[65536];

            int length = -1;
            try {
                while ((length = input.read(buffer)) >= 0) {
                    if (length > 0) output.write(buffer, 0, length);
                }
            } catch (IOException exception) {
                exception.printStackTrace(System.err);
            }
        }
    }


}
