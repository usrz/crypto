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

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class X509CertificateBuilder {

    public enum BasicKeyUsage {
        DIGITAL_SIGNATURE (KeyUsage.digitalSignature),
        NON_REPUDIATION   (KeyUsage.nonRepudiation),
        KEY_ENCIPHERMENT  (KeyUsage.keyEncipherment),
        DATA_ENCIPHERMENT (KeyUsage.keyEncipherment),
        KEY_AGREEMENT     (KeyUsage.keyAgreement),
        KEY_CERT_SIGN     (KeyUsage.keyCertSign),
        CRL_SIGN          (KeyUsage.cRLSign),
        ENCIPHER_ONLY     (KeyUsage.encipherOnly),
        DECIPHER_ONLY     (KeyUsage.decipherOnly);

        private int usage;

        private BasicKeyUsage(int usage) {
            this.usage = usage;
        }

        private static int combine(Collection<? extends BasicKeyUsage> collection) {
            int usage = 0;
            for (BasicKeyUsage flag: collection) {
                usage |= flag.usage;
            }
            return usage;
        }

    }

    public enum ExtendedKeyUsage {
        ANY              (KeyPurposeId.anyExtendedKeyUsage),
        SERVER_AUTH      (KeyPurposeId.id_kp_serverAuth),
        CLIENT_AUTH      (KeyPurposeId.id_kp_clientAuth),
        CODE_SIGNING     (KeyPurposeId.id_kp_codeSigning),
        EMAIL_PROTECTION (KeyPurposeId.id_kp_emailProtection),
        TIME_STAMPING    (KeyPurposeId.id_kp_timeStamping),
        OCSP_SIGNING     (KeyPurposeId.id_kp_OCSPSigning);

        private final KeyPurposeId id;

        private ExtendedKeyUsage(KeyPurposeId id) {
            this.id = id;
        }

        private static org.bouncycastle.asn1.x509.ExtendedKeyUsage combine(Collection<? extends ExtendedKeyUsage> collection) {
            final Set<KeyPurposeId> purposes = new HashSet<>();
            for (ExtendedKeyUsage usage: collection) purposes.add(usage.id);
            return new org.bouncycastle.asn1.x509.ExtendedKeyUsage(purposes.toArray(new KeyPurposeId[purposes.size()]));
        }
    }

    public enum Mode {
        CLIENT(new BasicKeyUsage[] { BasicKeyUsage.DIGITAL_SIGNATURE, BasicKeyUsage.KEY_ENCIPHERMENT },
               new ExtendedKeyUsage[]{ ExtendedKeyUsage.CLIENT_AUTH }),

        SERVER(new BasicKeyUsage[] { BasicKeyUsage.DIGITAL_SIGNATURE, BasicKeyUsage.KEY_ENCIPHERMENT },
               new ExtendedKeyUsage[]{ ExtendedKeyUsage.SERVER_AUTH }),

        AUTHORITY(new BasicKeyUsage[] { BasicKeyUsage.KEY_CERT_SIGN, BasicKeyUsage.CRL_SIGN },
                  new ExtendedKeyUsage[]{ ExtendedKeyUsage.OCSP_SIGNING });

        private Set<BasicKeyUsage> basic;
        private Set<ExtendedKeyUsage> extended;

        private Mode(BasicKeyUsage[] basic, ExtendedKeyUsage[] extended) {
            this.basic = basic.length == 0 ? Collections.<BasicKeyUsage>emptySet() : EnumSet.of(basic[0], basic);
            this.extended = extended.length == 0 ? Collections.<ExtendedKeyUsage>emptySet() : EnumSet.of(extended[0], extended);
        }
    }

    /* ====================================================================== */

    private X500Principal subject;
    private X500Principal issuer;
    private BigInteger serial;
    private Date notBefore;
    private Date notAfter;
    private PrivateKey issuerPrivateKey;
    private PublicKey issuerPublicKey;
    private PublicKey subjectPublicKey;
    private Mode mode;

    private final Set<BasicKeyUsage> basicKeyUsage = new HashSet<>();
    private final Set<ExtendedKeyUsage> extendedKeyUsage = new HashSet<>();
    private final List<GeneralName> alternativeNames = new ArrayList<>();
    private final Set<GeneralName> crlDistributionPoints = new HashSet<>();

    /* ====================================================================== */

    public X509CertificateBuilder() {
        this(null);
    }

    public X509CertificateBuilder(Mode mode) {

        /* Default "notBefore" to now, "notAfter" to one year later! */
        final long now = System.currentTimeMillis();
        notBefore = new Date(now);
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(notBefore);
        calendar.add(Calendar.YEAR, 1);
        notAfter = calendar.getTime();

        /* Set the default mode */
        mode(mode);
    }

    /* ====================================================================== */

    public X509Certificate build()
    throws CertificateException {
        if (subject == null) throw new IllegalStateException("Subject not specified");
        if (issuer == null) throw new IllegalStateException("Issuer not specified");
        if (serial == null) throw new IllegalStateException("Serial not specified");
        if (!notAfter.after(notBefore)) throw new IllegalStateException("Date \"not-after\" before or equal to \"not-before\"");
        if (issuerPrivateKey == null) throw new IllegalStateException("Issuer private key not specified");
        if (subjectPublicKey == null) throw new IllegalStateException("Sobject public key not specified");

        /* Basic subject public key and X500 names */
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded());
        final X500Name subjectName = X500Name.getInstance(subject.getEncoded());
        final X500Name issuerName = X500Name.getInstance(issuer.getEncoded());

        /* Derive the issuer public key from the private one if needed/possible */
        if ((issuerPublicKey == null) && (issuerPrivateKey instanceof RSAPrivateCrtKey)) try {
            final RSAPrivateCrtKey key = (RSAPrivateCrtKey) issuerPrivateKey;
            final RSAPublicKeySpec spec = new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent());
            issuerPublicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException exception) {
            Logger.getLogger(this.getClass().getName()).log(Level.FINE, "Unable to generate public key from private", exception);
        }

        final X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, subjectPublicKeyInfo);

        try {
            final JcaX509ExtensionUtils utils = new JcaX509ExtensionUtils();

            /* Are we a certificate authority? */
            certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(Mode.AUTHORITY.equals(mode)));

            /* Add our subject key identifier */
            certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, utils.createSubjectKeyIdentifier(subjectPublicKeyInfo));

            /* Do we have basic key usages? */
            if (!basicKeyUsage.isEmpty())
                certificateBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(BasicKeyUsage.combine(basicKeyUsage)));

            /* Do we have extended key usages? */
            if (!extendedKeyUsage.isEmpty())
                certificateBuilder.addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage.combine(extendedKeyUsage));

            /* Add our authority key identifer */
            if (issuerPublicKey != null) {
                final SubjectPublicKeyInfo authorityPublicKeyInfo = SubjectPublicKeyInfo.getInstance(issuerPublicKey.getEncoded());
                certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, utils.createAuthorityKeyIdentifier(authorityPublicKeyInfo));
            }

            /* Add our alternative names */
            if (!alternativeNames.isEmpty()) {
                final GeneralName[] names = alternativeNames.toArray(new GeneralName[alternativeNames.size()]);
                certificateBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
            }

            /* Add CRL distribution points */
            if (!crlDistributionPoints.isEmpty()) {
                final DistributionPoint[] distributionPoints = new DistributionPoint[crlDistributionPoints.size()];
                int position = 0;
                for (GeneralName generalName: crlDistributionPoints) {
                    final DistributionPointName distributionPointName = new DistributionPointName(new GeneralNames(generalName));
                    distributionPoints[position++] = new DistributionPoint(distributionPointName, null, null);
                }
                final CRLDistPoint crlDistributionPoint = new CRLDistPoint(distributionPoints);
                certificateBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistributionPoint);
            }

        } catch (CertIOException | NoSuchAlgorithmException exception) {
            throw new CertificateException("Exception adding extensions", exception);
        }

        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(issuerPrivateKey);
            final X509CertificateHolder certificateHolder = certificateBuilder.build(signer);
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));
        } catch (OperatorCreationException exception) {
            throw new CertificateException("Unable to create certificate signature", exception);
        } catch (IOException exception) {
            throw new CertificateException("Unable to generate certificate data", exception);
        }
    }

    /* ====================================================================== */

    public X509CertificateBuilder mode(Mode mode) {
        resetBasicKeyUsage();
        resetExtendedKeyUsage();
        if (mode != null) {
            basicKeyUsage.addAll(mode.basic);
            extendedKeyUsage.addAll(mode.extended);
        }
        this.mode = mode;
        return this;
    }

    public X509CertificateBuilder resetBasicKeyUsage() {
        basicKeyUsage.clear();
        return this;
    }

    public X509CertificateBuilder basicKeyUsage(BasicKeyUsage... basicUsages) {
        basicKeyUsage.addAll(Arrays.asList(basicUsages));
        return this;
    }

    public X509CertificateBuilder resetExtendedKeyUsage() {
        extendedKeyUsage.clear();
        return this;
    }

    public X509CertificateBuilder extendedKeyUsage(ExtendedKeyUsage... extendedUsages) {
        extendedKeyUsage.addAll(Arrays.asList(extendedUsages));
        return this;
    }

    /* ====================================================================== */

    public X509CertificateBuilder subject(X500Principal subject) {
        if (subject == null) throw new NullPointerException("Null subject");
        this.subject = subject;
        return this;
    }

    public X509CertificateBuilder subject(String subject) {
        if (subject == null) throw new NullPointerException("Null subject");
        return this.subject(new X500Principal(subject));
    }

    /* ====================================================================== */

    public X509CertificateBuilder issuer(X509Certificate issuer) {
        if (issuer == null) throw new NullPointerException("Null issuer");
        this.issuer = issuer.getSubjectX500Principal();
        issuerPublicKey = issuer.getPublicKey();

        final byte[] crl = issuer.getExtensionValue(Extension.cRLDistributionPoints.toString());
        if (crl != null) try {
            final DEROctetString value = (DEROctetString) ASN1Primitive.fromByteArray(crl);
            final CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(value.getOctets());
            for (DistributionPoint distPoint: crlDistPoint.getDistributionPoints()) {
                final DistributionPointName distPointName = distPoint.getDistributionPoint();
                final GeneralNames names = (GeneralNames) distPointName.getName();
                for (GeneralName name: names.getNames()) {
                    crlDistributionPoints.add(name);
                }
            }
        } catch (Exception exception) {
            Logger.getLogger(this.getClass().getName()).log(Level.WARNING, "Unable to parse CRL distribution points", exception);
        }

        return this;
    }

    public X509CertificateBuilder issuer(X500Principal issuer) {
        if (issuer == null) throw new NullPointerException("Null issuer");
        this.issuer = issuer;
        return this;
    }

    public X509CertificateBuilder issuer(String issuer) {
        if (issuer == null) throw new NullPointerException("Null issuer");
        return this.issuer(new X500Principal(issuer));
    }

    /* ====================================================================== */

    public X509CertificateBuilder serial(BigInteger serial) {
        if (serial == null) throw new NullPointerException("Null serial");
        if (serial.signum() != 1) throw new NullPointerException("Serial must be positive");
        this.serial = serial;
        return this;
    }

    public X509CertificateBuilder serial(long serial) {
        return this.serial(BigInteger.valueOf(serial));
    }

    /* ====================================================================== */

    public X509CertificateBuilder notBefore(Date notBefore) {
        if (notBefore == null) throw new NullPointerException("Null \"not-before\" date");
        this.notBefore = notBefore;
        return this;
    }

    public X509CertificateBuilder notBefore(long notBefore) {
        return this.notBefore(new Date(notBefore));
    }

    /* ====================================================================== */

    public X509CertificateBuilder notAfter(Date notAfter) {
        if (notAfter == null) throw new NullPointerException("Null \"not-after\" date");
        this.notAfter = notAfter;
        return this;
    }

    public X509CertificateBuilder notAfter(long notAfter) {
        return this.notAfter(new Date(notAfter));
    }

    public X509CertificateBuilder notAfter(long duration, TimeUnit unit) {
        if (notBefore == null) throw new IllegalStateException("Date \"not-before\" not yet specified");
        return this.notAfter(notBefore.getTime() + MILLISECONDS.convert(duration, unit));
    }

    /* ====================================================================== */

    public X509CertificateBuilder issuerPrivateKey(Key key) {
        if (key == null) throw new NullPointerException("Null issuer private key");
        try {
            issuerPrivateKey = (PrivateKey) key;
            return this;
        } catch (ClassCastException exception) {
            throw new IllegalArgumentException("Key " + key.getClass().getName() + " is not a private key");
        }
    }

    public X509CertificateBuilder issuerPublicKey(Key key) {
        if (key == null) throw new NullPointerException("Null issuer public key");
        try {
            issuerPublicKey = (PublicKey) key;
            return this;
        } catch (ClassCastException exception) {
            throw new IllegalArgumentException("Key " + key.getClass().getName() + " is not a public key");
        }
    }

    public X509CertificateBuilder issuerKeyPair(KeyPair keyPair) {
        if (keyPair == null) throw new NullPointerException("Null issuer key pair");
        issuerPrivateKey(keyPair.getPrivate());
        issuerPublicKey(keyPair.getPublic());
        return this;
    }

    public X509CertificateBuilder subjectPublicKey(Key key) {
        if (key == null) throw new NullPointerException("Null subject public key");
        try {
            subjectPublicKey = (PublicKey) key;
            return this;
        } catch (ClassCastException exception) {
            throw new IllegalArgumentException("Key " + key.getClass().getName() + " is not a public key");
        }
    }

    /* ====================================================================== */

    public X509CertificateBuilder resetAlternativeNames() {
        alternativeNames.clear();
        return this;
    }

    public X509CertificateBuilder alternativeNameEmail(String email) {
        if (email == null) throw new NullPointerException("Null email");
        alternativeNames.add(new GeneralName(GeneralName.rfc822Name, email));
        return this;
    }

    public X509CertificateBuilder alternativeNameDNS(String dnsName) {
        if (dnsName == null) throw new NullPointerException("Null DNS name");
        alternativeNames.add(new GeneralName(GeneralName.dNSName, dnsName));
        return this;
    }

    public X509CertificateBuilder alternativeNameURI(String uri) {
        if (uri == null) throw new NullPointerException("Null URI");
        return alternativeNameURI(URI.create(uri));
    }

    public X509CertificateBuilder alternativeNameURI(URL url) {
        if (url == null) throw new NullPointerException("Null URL");
        try {
            return alternativeNameURI(url.toURI());
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid URI " + url.toString(), exception);
        }
    }

    public X509CertificateBuilder alternativeNameURI(URI uri) {
        if (uri == null) throw new NullPointerException("Null URI");
        final String string = uri.toASCIIString();
        alternativeNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, string));
        return this;
    }

    public X509CertificateBuilder alternativeNameIPAddress(InetAddress address) {
        if (address == null) throw new NullPointerException("Null address");
        return this.alternativeNameIPAddress(address.getHostAddress());
    }

    public X509CertificateBuilder alternativeNameIPAddress(String address) {
        if (address == null) throw new NullPointerException("Null address");
        alternativeNames.add(new GeneralName(GeneralName.iPAddress, address));
        return this;
    }

    /* ====================================================================== */

    public X509CertificateBuilder resetCRLDistributionPuints() {
        crlDistributionPoints.clear();
        return this;
    }

    public X509CertificateBuilder crlDistributionPoint(String uri) {
        if (uri == null) throw new NullPointerException("Null CRL distribution point");
        return this.crlDistributionPoint(URI.create(uri));
    }

    public X509CertificateBuilder crlDistributionPoint(URL url) {
        if (url == null) throw new NullPointerException("Null CRL distribution point");
        try {
            return this.crlDistributionPoint(url.toURI());
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid URI " + url.toString(), exception);
        }
    }

    public X509CertificateBuilder crlDistributionPoint(URI uri) {
        if (uri == null) throw new NullPointerException("Null CRL distribution point");
        final String string = uri.toASCIIString();
        crlDistributionPoints.add(new GeneralName(GeneralName.uniformResourceIdentifier, string));
        return this;
    }

    /* ====================================================================== */

    public X509CertificateBuilder selfSigned(X500Principal principal, KeyPair keyPair) {
        if (principal == null) throw new NullPointerException("Null principal for self-signed certificate");
        if (keyPair == null) throw new NullPointerException("Null key pair for self-signed certificate");

        /* Set the mode (server) for self-signed certificates */
        mode(Mode.SERVER);

        /* Set the serial to the CRC32 of the subject */
        final CRC32 crc = new CRC32();
        crc.update(principal.getEncoded());
        this.serial(crc.getValue());

        /* Set the subject public key and principal */
        subjectPublicKey(keyPair.getPublic());
        this.subject(principal);

        /* Set the issuer key pair and principal */
        issuerKeyPair(keyPair);
        this.issuer(principal);

        /* Dun! */
        return this;
    }

    public X509CertificateBuilder selfSigned(String principal, KeyPair keyPair) {
        if (subject == null) throw new NullPointerException("Null subject");
        return this.selfSigned(new X500Principal(principal), keyPair);
    }

}
