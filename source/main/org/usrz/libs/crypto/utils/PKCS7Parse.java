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
import java.security.cert.X509Certificate;

import sun.security.pkcs.PKCS7;
import sun.security.pkcs.SignerInfo;
import sun.security.x509.AlgorithmId;

public class PKCS7Parse {

    public static void main(String[] args)
    throws Throwable {
        final ByteArrayOutputStream data = new ByteArrayOutputStream();
        final byte[] buffer = new byte[65535];

        int length = -1;
        while ((length = System.in.read(buffer)) >= 0) {
            if (length > 0) data.write(buffer, 0, length);
        }

        PKCS7 pkcs7 = new PKCS7(data.toByteArray());
        System.err.println("CERTs: " + pkcs7.getCertificates());
        if (pkcs7.getCertificates() != null) {
            for (X509Certificate cert: pkcs7.getCertificates()) {
                System.err.println("     : " + cert.getSubjectDN());
            }
        }

        System.err.println("Content Info: " + pkcs7.getContentInfo());
        System.err.println("CRLs: " + pkcs7.getCRLs());
        System.err.println("DIGESTs: " + pkcs7.getDigestAlgorithmIds());
        if (pkcs7.getDigestAlgorithmIds() != null) {
            for (AlgorithmId algo: pkcs7.getDigestAlgorithmIds()) {
                System.err.println("       : " + algo.getName());
            }
        }

        System.err.println("SIGNERs: " + pkcs7.getSignerInfos());
        if (pkcs7.getSignerInfos() != null) {
            for (SignerInfo sign: pkcs7.getSignerInfos()) {
                System.err.println("       : " + sign);
            }
        }

        System.err.println("VERSION: " + pkcs7.getVersion());
    }
}
