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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.security.auth.x500.X500Principal;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.usrz.libs.crypto.codecs.HexCodec;
import org.usrz.libs.logging.Log;
import org.usrz.libs.logging.Logging;

public class PEMKeyStoreTest {

    static { Logging.init(); }

    private static final Log log = new Log();

    /* Equifax-based (Eqyufax Secure is self-signed) */
    private static final X500Principal WWW_YAHOO_COM     = new X500Principal("CN=www.yahoo.com, O=\"Yahoo  Inc.\", L=Sunnyvale, ST=California, C=US, SERIALNUMBER=2g8aO5wI1bKJ2ZD588UsLvDe3gTbg8DU");
    private static final X500Principal WWW_GOOGLE_COM    = new X500Principal("CN=www.google.com, O=Google Inc, L=Mountain View, ST=California, C=US");
    private static final X500Principal GOOGLE_AUTHORITY  = new X500Principal("CN=Google Internet Authority G2, O=Google Inc, C=US");
    private static final X500Principal GEOTRUST_GLOBAL   = new X500Principal("CN=GeoTrust Global CA, O=GeoTrust Inc., C=US");
    private static final X500Principal EQUIFAX_SECURE    = new X500Principal("OU=Equifax Secure Certificate Authority, O=Equifax, C=US");

    /* Verisign seems to be encoding text as "TeleTextString" instead of "PrintableString"/"UTF8String" in their ASN.1. */
    // "CN=*.facebook.com, O=\"Facebook, Inc.\", L=Palo Alto, ST=California, C=US"
    private static final X500Principal WWW_FACEBOOK_COM  = new X500Principal(HexCodec.HEX.decode("3068310B3009060355040613025553311330110603550408130A43616C69666F726E6961311230100603550407140950616C6F20416C746F31173015060355040A140E46616365626F6F6B2C20496E632E311730150603550403140E2A2E66616365626F6F6B2E636F6D"));
    // "CN=www.apple.com, OU=ISG for Akamai, O=Apple Inc., STREET=1 Infinite Loop, L=Cupertino, ST=California, OID.2.5.4.17=95014, C=US, SERIALNUMBER=C0806592, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=California, OID.1.3.6.1.4.1.311.60.2.1.3=US"
    private static final X500Principal WWW_APPLE_COM     = new X500Principal(HexCodec.HEX.decode("3082010A31133011060B2B0601040182373C02010313025553311B3019060B2B0601040182373C020102130A43616C69666F726E6961311D301B060355040F131450726976617465204F7267616E697A6174696F6E3111300F060355040513084330383036353932310B3009060355040613025553310E300C060355041114053935303134311330110603550408130A43616C69666F726E69613112301006035504071409437570657274696E6F311830160603550409140F3120496E66696E697465204C6F6F7031133011060355040A140A4170706C6520496E632E31173015060355040B140E49534720666F7220416B616D6169311630140603550403140D7777772E6170706C652E636F6D"));
    private static final X500Principal VERISIGN_SERVER   = new X500Principal("CN=VeriSign Class 3 Secure Server CA - G3, OU=Terms of use at https://www.verisign.com/rpa (c)10, OU=VeriSign Trust Network, O=\"VeriSign, Inc.\", C=US");
    private static final X500Principal VERISIGN_EXTENDED = new X500Principal("CN=VeriSign Class 3 Extended Validation SSL SGC CA, OU=Terms of use at https://www.verisign.com/rpa (c)06, OU=VeriSign Trust Network, O=\"VeriSign, Inc.\", C=US");
    private static final X500Principal VERISIGN_PRIMARY  = new X500Principal("CN=VeriSign Class 3 Public Primary Certification Authority - G5, OU=\"(c) 2006 VeriSign, Inc. - For authorized use only\", OU=VeriSign Trust Network, O=\"VeriSign, Inc.\", C=US");

    /* GoDaddy-based, we don't supply their root (broken chain, but still go up please  */
    private static final X500Principal WWW_GILT_COM      = new X500Principal("CN=www.gilt.com, O=\"Gilt Groupe, Inc.\", L=New York, ST=New York, C=US, SERIALNUMBER=4186813, OID.2.5.4.15=Private Organization, OID.1.3.6.1.4.1.311.60.2.1.2=New York, OID.1.3.6.1.4.1.311.60.2.1.3=US");
    private static final X500Principal GODADDY_SECURE    = new X500Principal("SERIALNUMBER=07969287, CN=Go Daddy Secure Certification Authority, OU=http://certificates.godaddy.com/repository, O=\"GoDaddy.com, Inc.\", L=Scottsdale, ST=Arizona, C=US");

    @Test
    public void testCertificatesAndChain()
    throws Throwable {
        Security.addProvider(new PEMProvider());

        final KeyStore keyStore = KeyStore.getInstance("PEM");
        keyStore.load(this.getClass().getResourceAsStream("chains.pem"), null);

        final Map<X500Principal, X509Certificate> certificates = new HashMap<>();
        final Map<X500Principal, String> certificateAliases = new HashMap<>();

        final Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            final String alias = aliases.nextElement();
            final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
            final X500Principal principal = certificate.getSubjectX500Principal();

            Assert.assertEquals(alias, keyStore.getCertificateAlias(certificate), "Alias mismatch");

            certificates.put(principal, certificate);
            certificateAliases.put(principal, alias);
            log.debug("Found certificate \"%s\"", principal);
            log.debug("            ASN.1 \"%s\"", HexCodec.HEX.encode(principal.getEncoded()));
        }

        Assert.assertEquals(certificates.size(), 12, "Wrong number of certificates");
        Assert.assertTrue(certificates.containsKey(EQUIFAX_SECURE),    "Certificate for Equifax Secure not found");
        Assert.assertTrue(certificates.containsKey(GEOTRUST_GLOBAL),   "Certificate for Geotrust Global not found");
        Assert.assertTrue(certificates.containsKey(GODADDY_SECURE),    "Certificate for GoDaddy Secure not found");
        Assert.assertTrue(certificates.containsKey(GOOGLE_AUTHORITY),  "Certificate for Google Authority not found");
        Assert.assertTrue(certificates.containsKey(VERISIGN_EXTENDED), "Certificate for VeriSign Extended");
        Assert.assertTrue(certificates.containsKey(VERISIGN_PRIMARY),  "Certificate for VeriSign Primary");
        Assert.assertTrue(certificates.containsKey(VERISIGN_SERVER),   "Certificate for VeriSign Server");
        Assert.assertTrue(certificates.containsKey(WWW_APPLE_COM),     "Certificate for WWW.APPLE.COM not found");
        Assert.assertTrue(certificates.containsKey(WWW_FACEBOOK_COM),  "Certificate for WWW.FACEBOOK.COM not found");
        Assert.assertTrue(certificates.containsKey(WWW_GILT_COM),      "Certificate for WWW.GILT.COM not found");
        Assert.assertTrue(certificates.containsKey(WWW_GOOGLE_COM),    "Certificate for WWW.GOOGLE.COM not found");
        Assert.assertTrue(certificates.containsKey(WWW_YAHOO_COM),     "Certificate for WWW.YAHOO.COM not found");

        /* Apple's chain */
        validateChain(keyStore, certificateAliases.get(WWW_APPLE_COM),
                      certificates.get(WWW_APPLE_COM),
                      certificates.get(VERISIGN_EXTENDED),
                      certificates.get(VERISIGN_PRIMARY));

        validateChain(keyStore, certificateAliases.get(VERISIGN_EXTENDED),
                      certificates.get(VERISIGN_EXTENDED),
                      certificates.get(VERISIGN_PRIMARY));

        validateChain(keyStore, certificateAliases.get(VERISIGN_PRIMARY),
                      certificates.get(VERISIGN_PRIMARY));

        /* Facebook's chain */
        validateChain(keyStore, certificateAliases.get(WWW_FACEBOOK_COM),
                      certificates.get(WWW_FACEBOOK_COM),
                      certificates.get(VERISIGN_SERVER),
                      certificates.get(VERISIGN_PRIMARY));

        validateChain(keyStore, certificateAliases.get(VERISIGN_SERVER),
                      certificates.get(VERISIGN_SERVER),
                      certificates.get(VERISIGN_PRIMARY));

        /* Gilt's chain */
        validateChain(keyStore, certificateAliases.get(WWW_GILT_COM),
                      certificates.get(WWW_GILT_COM),
                      certificates.get(GODADDY_SECURE));

        validateChain(keyStore, certificateAliases.get(GODADDY_SECURE),
                      certificates.get(GODADDY_SECURE));

        /* Google's chain */
        validateChain(keyStore, certificateAliases.get(WWW_GOOGLE_COM),
                      certificates.get(WWW_GOOGLE_COM),
                      certificates.get(GOOGLE_AUTHORITY),
                      certificates.get(GEOTRUST_GLOBAL),
                      certificates.get(EQUIFAX_SECURE));

        validateChain(keyStore, certificateAliases.get(GOOGLE_AUTHORITY),
                      certificates.get(GOOGLE_AUTHORITY),
                      certificates.get(GEOTRUST_GLOBAL),
                      certificates.get(EQUIFAX_SECURE));

        validateChain(keyStore, certificateAliases.get(GEOTRUST_GLOBAL),
                      certificates.get(GEOTRUST_GLOBAL),
                      certificates.get(EQUIFAX_SECURE));

        validateChain(keyStore, certificateAliases.get(EQUIFAX_SECURE),
                      certificates.get(EQUIFAX_SECURE));

        /* Yahoo's chain */
        validateChain(keyStore, certificateAliases.get(WWW_YAHOO_COM),
                      certificates.get(WWW_YAHOO_COM),
                      certificates.get(EQUIFAX_SECURE));

    }

    private final void validateChain(KeyStore keyStore, String alias, X509Certificate... certificates)
    throws KeyStoreException {
        final String chainName = certificates[0].getSubjectX500Principal().toString();

        final Certificate[] chain = keyStore.getCertificateChain(alias);
        Assert.assertNotNull(chain, "Certificate chain for " + chainName + " is null");

        log.debug("Dumping contents for chain %s:", chainName);
        for (int x = 0; x < chain.length; x++) {
            final X509Certificate certificate = (X509Certificate) chain[x];
            log.debug("--[%d]--+--(subject)--> %s", x, certificate.getSubjectX500Principal());
            log.debug("       +--(issuer )--> %s", certificate.getIssuerX500Principal());
        }

        Assert.assertEquals(chain.length, certificates.length, "Wrong number of certificates in chain for " + chainName);
        for (int x = 0; x < chain.length; x++) {
            Assert.assertEquals(chain[x], certificates[x], "Wrong certificate at position " + x + " in chain for " + chainName);
        }
    }


    @Test(expectedExceptions=IllegalStateException.class,
          expectedExceptionsMessageRegExp="^Duplicate key .* found in PEM file")
    public void testKeys()
    throws Throwable {
        Security.addProvider(new PEMProvider());

        final KeyStore keyStore = KeyStore.getInstance("PEM");
        keyStore.load(this.getClass().getResourceAsStream("keys.pem"), "asdf".toCharArray());

    }

    @Test
    public void testSelfSigned()
    throws Throwable {
        Security.addProvider(new PEMProvider());

        final X500Principal principal = new X500Principal("CN=Testing Self-Signed Certificate, OU=Testing Framework, O=USRZ.org, L=Shinjuku, ST=Tokyo, C=JP");

        final KeyStore keyStore = KeyStore.getInstance("PEM");
        keyStore.load(this.getClass().getResourceAsStream("selfsigned.pem"), "asdf".toCharArray());

        final RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey("F7A4FD46266A272B145B4F09F6D14CC7A458268B", "asdf".toCharArray());
        Assert.assertNotNull(key, "Private key is null");

        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate("F7A4FD46266A272B145B4F09F6D14CC7A458268B");
        Assert.assertNotNull(certificate, "Certificate is null");
        Assert.assertEquals(certificate.getSubjectX500Principal(), principal);
        Assert.assertEquals(certificate.getIssuerX500Principal(), principal);

        final RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        Assert.assertNotNull(publicKey, "Public key is null");
        Assert.assertEquals(publicKey.getModulus(), key.getModulus());
        Assert.assertEquals(publicKey.getPublicExponent(), key.getPublicExponent());

        validateChain(keyStore, "F7A4FD46266A272B145B4F09F6D14CC7A458268B", certificate);

    }

    @Test
    public void testFullSigned()
    throws Throwable {
        Security.addProvider(new PEMProvider());

        final X500Principal subject = new X500Principal("CN=Testing Certificate, OU=Testing Framework, O=USRZ.org, ST=Tokyo, C=JP");
        final X500Principal issuer = new X500Principal("CN=Testing Intermediate Certificate Authority, OU=Testing Framework, O=USRZ.org, ST=Tokyo, C=JP");

        final KeyStore keyStore = KeyStore.getInstance("PEM");
        keyStore.load(this.getClass().getResourceAsStream("full.pem"), "asdf".toCharArray());

        final RSAPrivateCrtKey key = (RSAPrivateCrtKey) keyStore.getKey("9D31E8423D144DD51E16BBAAB8A7E0C117B32F7E", "asdf".toCharArray());
        Assert.assertNotNull(key, "Private key is null");

        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate("9D31E8423D144DD51E16BBAAB8A7E0C117B32F7E");
        Assert.assertNotNull(certificate, "Certificate is null");
        Assert.assertEquals(certificate.getSubjectX500Principal(), subject);
        Assert.assertEquals(certificate.getIssuerX500Principal(), issuer);

        final RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
        Assert.assertNotNull(publicKey, "Public key is null");
        Assert.assertEquals(publicKey.getModulus(), key.getModulus());
        Assert.assertEquals(publicKey.getPublicExponent(), key.getPublicExponent());

        validateChain(keyStore, "9D31E8423D144DD51E16BBAAB8A7E0C117B32F7E",
                      certificate,
                      (X509Certificate) keyStore.getCertificate("377177A2311D78FEEAAA8D3F67D2B60C4A1E1966"),
                      (X509Certificate) keyStore.getCertificate("D5F522D0BF37CF9134603060F6D04B235A74CC70"));

    }

    @Test
    public void testMultipleInitializations()
    throws Exception {
        Security.addProvider(new PEMProvider());
        final KeyStore keyStore = KeyStore.getInstance("PEM");

        keyStore.load(this.getClass().getResourceAsStream("selfsigned.pem"), "asdf".toCharArray());
        Assert.assertEquals(keyStore.size(), 1); // 1 entry, self signed key/cert

        keyStore.load(this.getClass().getResourceAsStream("full.pem"), "asdf".toCharArray());
        Assert.assertEquals(keyStore.size(), 4); // 4 entries, self signed key/cert, key/cert, intermediate CA, root CA
    }

    @Test
    public void testSSLContext()
    throws Exception {
        Security.addProvider(new PEMProvider());

        final KeyStore keyStore = KeyStore.getInstance("PEM");
        keyStore.load(this.getClass().getResourceAsStream("selfsigned.pem"), "asdf".toCharArray());

        final KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyFactory.init(keyStore, "asdf".toCharArray());

        final TrustManagerFactory trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(keyStore);

        final SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyFactory.getKeyManagers(), trustFactory.getTrustManagers(), null);

        final InetAddress localhost = InetAddress.getLoopbackAddress();
        final ServerSocket server = context.getServerSocketFactory().createServerSocket(0, 1, localhost);
        log.debug("ServerSocket bound to port %s", server.getLocalSocketAddress());

        final Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    final Socket s = server.accept();
                    log.debug("Accepting connection from %s" + s.getRemoteSocketAddress());
                    s.getOutputStream().write("HELLO!".getBytes());
                    s.close();
                } catch (Exception exception) {
                    exception.printStackTrace();
                }
            }
        });

        try {
            thread.start();

            final Socket client = context.getSocketFactory().createSocket(localhost, server.getLocalPort());
            final ByteArrayOutputStream output = new ByteArrayOutputStream();
            final InputStream input = client.getInputStream();
            final byte[] buffer = new byte[128];

            int read = -1;
            while ((read = input.read(buffer)) >= 0) {
                if (read > 0) output.write(buffer, 0, read);
            }
            input.close();
            output.close();

            Assert.assertEquals(new String(output.toByteArray()), "HELLO!");
        } finally {
            try {
                server.close();
            } finally {
                thread.interrupt();
            }
            thread.join();
        }
    }

}
