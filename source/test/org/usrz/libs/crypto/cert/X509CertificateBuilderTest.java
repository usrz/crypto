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
package org.usrz.libs.crypto.cert;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.testng.annotations.Test;
import org.usrz.libs.crypto.cert.X509CertificateBuilder.Mode;
import org.usrz.libs.crypto.codecs.HexCodec;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.testing.Exec;
import org.usrz.libs.testing.Exec.CapturingProcess;
import org.usrz.libs.testing.IO;

public class X509CertificateBuilderTest extends AbstractTest {

    @Test
    public void testServerCertificate()
    throws Exception {
        final KeyPair keyPair = new KeyPairBuilder().build();

        final X500Principal principal = new X500PrincipalBuilder()
                .country("JP")
                .state("Tokyo")
                .locality("Shinjuku")
                .organisation("USRZ.org")
                .organisationalUnit("Automated Tests")
                .commonName("localhost")
                .emailAddress("noreply@usrz.org")
                .build();
        assertEquals(principal, new X500Principal("EMAILADDRESS=noreply@usrz.org, CN=localhost, OU=Automated Tests, O=USRZ.org, L=Shinjuku, ST=Tokyo, C=JP"));

        final X509Certificate certificate = new X509CertificateBuilder()
                .selfSigned(principal, keyPair)
                .notBefore(0)
                .notAfter(1, TimeUnit.DAYS)
                .alternativeNameDNS("localhost")
                .alternativeNameIPAddress("127.0.0.1")
                .alternativeNameIPAddress("::1")
                .alternativeNameURI("https://127.0.0.1/")
                .crlDistributionPoint("https://usrz.org/test1.crl")
                .crlDistributionPoint("https://usrz.org/test2.crl")
                .build();

        assertEquals(certificate.getVersion(), 3, "Wrong version");
        assertEquals(certificate.getSubjectX500Principal(), principal, "Wrong subject");
        assertEquals(certificate.getIssuerX500Principal(), principal, "Wrong issuer");
        assertEquals(certificate.getPublicKey(), keyPair.getPublic(), "Wrong public key");
        assertEquals(certificate.getSigAlgName(), "SHA1withRSA", "Wrong algorithm");
        assertEquals(certificate.getNotBefore(), new Date(0), "Wrong \"not-before\" date");
        assertEquals(certificate.getNotAfter(), new Date(86400000), "Wrong \"not-after\" date");
        assertEquals(certificate.getBasicConstraints(), -1, "Wrong basic constraints");
        assertEquals(certificate.getKeyUsage(), new boolean[] {
                                true,   // digitalSignature
                                false,  // nonRepudiation
                                true,   // keyEncipherment
                                false,  // dataEncipherment
                                false,  // keyAgreement
                                false,  // keyCertSign
                                false,  // cRLSign
                                false,  // encipherOnly
                                false}, // decipherOnly
                    "Wrong basic key usage");
        assertEqualsNoOrder(certificate.getExtendedKeyUsage().toArray(),
                            new Object[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" },
                            "Wrong extended key usage: " + certificate.getExtendedKeyUsage());

        final Set<String> alternativeNames = new HashSet<>();
        for (List<?> alternativeName: certificate.getSubjectAlternativeNames()) {
            alternativeNames.add(alternativeName.toString());
        }

        assertEqualsNoOrder(alternativeNames.toArray(),
                            new Object[] { "[2, localhost]",
                                           "[7, 127.0.0.1]",
                                           "[7, 0:0:0:0:0:0:0:1]",
                                           "[6, https://127.0.0.1/]" },
                            "Wrong alternative names: " + certificate.getSubjectAlternativeNames());

        assertEquals(certificate.getExtensionValue("2.5.29.31"),
                     HexCodec.HEX.decode("044630443020A01EA01C861A68747470733A2F2F7573727A2E6F72672F74657374322E63726C3020A01EA01C861A68747470733A2F2F7573727A2E6F72672F74657374312E63726C"),
                     "Wrong CRL distribution points" + HexCodec.HEX.encode(certificate.getExtensionValue("2.5.29.31")));

        assertEquals(HexCodec.HEX.encode(certificate.getExtensionValue("2.5.29.14")).substring(8),  // subject key ID minus ASN.1 header
                     HexCodec.HEX.encode(certificate.getExtensionValue("2.5.29.35")).substring(12), // authority key ID minus ASN.1 header
                     "Key Identifiers Mismatch");

        final File file = IO.makeTempFile(".der");
        IO.copy(certificate.getEncoded(), file);
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text",
                    "-in", file.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");

    }

    @Test
    public void testAuthorityCertificate()
    throws Exception {
        final KeyPair keyPair = new KeyPairBuilder().build();

        final X500Principal principal = new X500PrincipalBuilder()
                .country("JP")
                .state("Tokyo")
                .locality("Shinjuku")
                .organisation("USRZ.org")
                .organisationalUnit("Automated Tests")
                .commonName("Test Certificate Authority")
                .emailAddress("noreply@usrz.org")
                .build();
        assertEquals(principal, new X500Principal("EMAILADDRESS=noreply@usrz.org, CN=Test Certificate Authority, OU=Automated Tests, O=USRZ.org, L=Shinjuku, ST=Tokyo, C=JP"));

        final X509Certificate certificate = new X509CertificateBuilder()
                .selfSigned(principal, keyPair)
                .mode(Mode.AUTHORITY)
                .notBefore(0)
                .notAfter(1, TimeUnit.DAYS)
                .crlDistributionPoint("https://usrz.org/test.crl")
                .build();

        assertEquals(certificate.getVersion(), 3, "Wrong version");
        assertEquals(certificate.getSubjectX500Principal(), principal, "Wrong subject");
        assertEquals(certificate.getIssuerX500Principal(), principal, "Wrong issuer");
        assertEquals(certificate.getPublicKey(), keyPair.getPublic(), "Wrong public key");
        assertEquals(certificate.getSigAlgName(), "SHA1withRSA", "Wrong algorithm");
        assertEquals(certificate.getNotBefore(), new Date(0), "Wrong \"not-before\" date");
        assertEquals(certificate.getNotAfter(), new Date(86400000), "Wrong \"not-after\" date");
        assertEquals(certificate.getBasicConstraints(), Integer.MAX_VALUE, "Wrong basic constraints");
        assertEquals(certificate.getKeyUsage(), new boolean[] {
                                false,  // digitalSignature
                                false,  // nonRepudiation
                                false,  // keyEncipherment
                                false,  // dataEncipherment
                                false,  // keyAgreement
                                true,   // keyCertSign
                                true,   // cRLSign
                                false,  // encipherOnly
                                false}, // decipherOnly
                    "Wrong basic key usage");
        assertNull(certificate.getExtendedKeyUsage(), "Wrong extended key usage: " + certificate.getExtendedKeyUsage());
        assertNull(certificate.getSubjectAlternativeNames(), "Wrong alternative names: " + certificate.getSubjectAlternativeNames());

        assertEquals(certificate.getExtensionValue("2.5.29.31"),
                     HexCodec.HEX.decode("04233021301FA01DA01B861968747470733A2F2F7573727A2E6F72672F746573742E63726C"),
                     "Wrong CRL distribution points: " + HexCodec.HEX.encode(certificate.getExtensionValue("2.5.29.31")));

        assertEquals(HexCodec.HEX.encode(certificate.getExtensionValue("2.5.29.14")).substring(8),  // subject key ID minus ASN.1 header
                     HexCodec.HEX.encode(certificate.getExtensionValue("2.5.29.35")).substring(12), // authority key ID minus ASN.1 header
                     "Key Identifiers Mismatch");

        final File file = IO.makeTempFile(".der");
        IO.copy(certificate.getEncoded(), file);
        IO.copy(certificate.getEncoded(), new File("temp.der"));
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text",
                    "-in", file.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");
    }

    @Test
    public void testCASign()
    throws Exception {
        final KeyPair authorityKeyPair = new KeyPairBuilder().build();

        final X500Principal authorityPrincipal = new X500PrincipalBuilder()
                .country("JP")
                .state("Tokyo")
                .locality("Shinjuku")
                .organisation("USRZ.org")
                .organisationalUnit("Automated Tests")
                .commonName("Test Certificate Authority")
                .emailAddress("noreply@usrz.org")
                .build();

        final X509Certificate authorityCertificate = new X509CertificateBuilder()
                .selfSigned(authorityPrincipal, authorityKeyPair)
                .mode(Mode.AUTHORITY)
                .crlDistributionPoint("https://usrz.org/test.crl")
                .build();

        final File authorityFile = IO.makeTempFile("authority", ".der");
        final File authorityFilePEM = IO.makeTempFile("authority", ".pem");
        IO.copy(authorityCertificate.getEncoded(), authorityFile);
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text",
                    "-out", authorityFilePEM.getAbsolutePath(),
                    "-in", authorityFile.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text", "-noout",
                    "-in", authorityFile.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");

        assertPurpose("sslclient",    true,  authorityFilePEM, authorityFilePEM);
        assertPurpose("sslserver",    true,  authorityFilePEM, authorityFilePEM);
        assertPurpose("nssslserver",  true,  authorityFilePEM, authorityFilePEM);
        assertPurpose("smimesign",    true,  authorityFilePEM, authorityFilePEM);
        assertPurpose("smimeencrypt", true,  authorityFilePEM, authorityFilePEM);
        assertPurpose("crlsign",      true,  authorityFilePEM, authorityFilePEM);
        assertPurpose("any",          true,  authorityFilePEM, authorityFilePEM);
        assertPurpose("ocsphelper",   true,  authorityFilePEM, authorityFilePEM);

        /* ================================================================== */

        final KeyPair serverKeyPair = new KeyPairBuilder().build();

        final X500Principal serverPrincipal = new X500PrincipalBuilder()
                .country("JP")
                .state("Tokyo")
                .locality("Shinjuku")
                .organisation("USRZ.org")
                .organisationalUnit("Automated Tests")
                .commonName("localhost")
                .emailAddress("noreply@usrz.org")
                .build();

        final X509Certificate serverCertificate = new X509CertificateBuilder()
                .mode(Mode.SERVER)
                .issuer(authorityCertificate)
                .issuerPrivateKey(authorityKeyPair.getPrivate())
                .subject(serverPrincipal)
                .subjectPublicKey(serverKeyPair.getPublic())
                .serial(1)
                .build();

        final File serverFile = IO.makeTempFile("server", ".der");
        final File serverFilePEM = IO.makeTempFile("server", ".pem");
        IO.copy(serverCertificate.getEncoded(), serverFile);
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text",
                    "-out", serverFilePEM.getAbsolutePath(),
                    "-in", serverFile.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text", "-noout",
                    "-in", serverFile.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");

        assertPurpose("sslclient",    false, authorityFilePEM, serverFilePEM);
        assertPurpose("sslserver",    true,  authorityFilePEM, serverFilePEM);
        assertPurpose("nssslserver",  true,  authorityFilePEM, serverFilePEM);
        assertPurpose("smimesign",    false, authorityFilePEM, serverFilePEM);
        assertPurpose("smimeencrypt", false, authorityFilePEM, serverFilePEM);
        assertPurpose("crlsign",      false, authorityFilePEM, serverFilePEM);
        assertPurpose("any",          true,  authorityFilePEM, serverFilePEM);
        assertPurpose("ocsphelper",   true,  authorityFilePEM, serverFilePEM);

        /* ================================================================== */

        final KeyPair clientKeyPair = new KeyPairBuilder().build();

        final X500Principal clientPrincipal = new X500PrincipalBuilder()
                .country("JP")
                .state("Tokyo")
                .locality("Shinjuku")
                .organisation("USRZ.org")
                .organisationalUnit("Automated Tests")
                .commonName("John Doe")
                .emailAddress("noreply@usrz.org")
                .build();

        final X509Certificate clientCertificate = new X509CertificateBuilder()
                .mode(Mode.CLIENT)
                .issuer(authorityCertificate)
                .issuerPrivateKey(authorityKeyPair.getPrivate())
                .subject(clientPrincipal)
                .subjectPublicKey(clientKeyPair.getPublic())
                .serial(1)
                .build();

        final File clientFile = IO.makeTempFile("client", ".der");
        final File clientFilePEM = IO.makeTempFile("client", ".pem");
        IO.copy(clientCertificate.getEncoded(), clientFile);
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text",
                    "-out", clientFilePEM.getAbsolutePath(),
                    "-in", clientFile.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");
        assertEquals(Exec.exec(new String[] {
                    "openssl", "x509", "-inform", "DER", "-text", "-noout",
                    "-in", clientFile.getAbsolutePath() }).waitFor(),
                0, "OpenSSL failure");

        assertPurpose("sslclient",    true,  authorityFilePEM, clientFilePEM);
        assertPurpose("sslserver",    false, authorityFilePEM, clientFilePEM);
        assertPurpose("nssslserver",  false, authorityFilePEM, clientFilePEM);
        assertPurpose("smimesign",    false, authorityFilePEM, clientFilePEM);
        assertPurpose("smimeencrypt", false, authorityFilePEM, clientFilePEM);
        assertPurpose("crlsign",      false, authorityFilePEM, clientFilePEM);
        assertPurpose("any",          true,  authorityFilePEM, clientFilePEM);
        assertPurpose("ocsphelper",   true,  authorityFilePEM, clientFilePEM);

        /* ================================================================== */

        assertEquals(serverCertificate.getIssuerX500Principal(),
                     authorityCertificate.getSubjectX500Principal(),
                     "Wrong issuer principal");
        assertEquals(clientCertificate.getIssuerX500Principal(),
                     authorityCertificate.getSubjectX500Principal(),
                     "Wrong issuer principal");

        assertEquals(serverCertificate.getExtensionValue("2.5.29.31"),
                     authorityCertificate.getExtensionValue("2.5.29.31"),
                     "Wrong CRL distribution list");

        assertEquals(clientCertificate.getExtensionValue("2.5.29.31"),
                     authorityCertificate.getExtensionValue("2.5.29.31"),
                     "Wrong CRL distribution list");

        assertEquals(HexCodec.HEX.encode(serverCertificate.getExtensionValue("2.5.29.35")).substring(12), // authority key ID minus ASN.1 header
                     HexCodec.HEX.encode(authorityCertificate.getExtensionValue("2.5.29.14")).substring(8),  // subject key ID minus ASN.1 header
                     "Key Identifiers Mismatch");

        assertEquals(HexCodec.HEX.encode(clientCertificate.getExtensionValue("2.5.29.35")).substring(12), // authority key ID minus ASN.1 header
                     HexCodec.HEX.encode(authorityCertificate.getExtensionValue("2.5.29.14")).substring(8),  // subject key ID minus ASN.1 header
                     "Key Identifiers Mismatch");

    }

    /* ====================================================================== */

    private void assertPurpose(String purpose, boolean allowed, File authorityPem, File pem)
    throws Exception {
        final String string = verifyPurpose(purpose, authorityPem, pem);
        if (allowed) assertEquals(string, pem + ": OK", "Purpose \"" + purpose + "\" not allowed");
        else assertNotEquals(string, pem + ": OK", "Purpose \"" + purpose + "\" must not be allowed");
    }

    private String verifyPurpose(String purpose, File authorityPem, File pem)
    throws Exception {
        final CapturingProcess process = Exec.capture(new String[] {
                    "openssl", "verify", "-purpose", purpose,
                    "-CAfile", authorityPem.getAbsolutePath(),
                    pem.getAbsolutePath() });
        assertEquals(process.waitFor(), 0, "OpenSSL failure");
        return process.getOutput().trim() + process.getError().trim();
    }
}
