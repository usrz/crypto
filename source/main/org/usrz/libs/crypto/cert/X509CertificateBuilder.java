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

/**
 * A simple builder to create {@linkplain X509Certificate X.509 certificates}.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class X509CertificateBuilder {

    /**
     * An enumeration containing the possible <i>Standard key usages</i> supported
     * by a {@link X509CertificateBuilder}.
     *
     * <p>Key usage extensions define the purpose of the public key contained
     * in a certificate. You can use them to restrict the public key to as few
     * or as many operations as needed. For example, if you have a key used
     * only for signing or verifying a signature, enable the digital signature
     * and/or non-repudiation extensions. Alternatively, if a key is used only
     * for key management, enable key encipherment.</p>
     *
     * @see <a target="_blank" href="http://publib.boulder.ibm.com/infocenter/domhelp/v8r0/index.jsp?topic=%2Fcom.ibm.help.domino.admin.doc%2FDOC%2FH_KEY_USAGE_EXTENSIONS_FOR_INTERNET_CERTIFICATES_1521_OVER.html">IBM's reference</a>
     */
    public enum StandardKeyUsage {
        /**
         * Use when the public key is used with a digital signature mechanism
         * to support security services other than non-repudiation,
         * certificate signing, or CRL signing. A digital signature is often
         * used for entity authentication and data origin authentication with
         * integrity.
         */
        DIGITAL_SIGNATURE (KeyUsage.digitalSignature),

        /**
         * Use when the public key is used to verify digital signatures used
         * to provide a non-repudiation service. Non-repudiation protects
         * against the signing entity falsely denying some action (excluding
         * certificate or CRL signing).
         */
        NON_REPUDIATION   (KeyUsage.nonRepudiation),

        /**
         * Use when a certificate will be used with a protocol that encrypts
         * keys. An example is S/MIME enveloping, where a fast (symmetric) key
         * is encrypted with the public key from the certificate. SSL protocol
         * also performs key encipherment.
         */
        KEY_ENCIPHERMENT  (KeyUsage.keyEncipherment),

        /**
         * Use when the public key is used for encrypting user data, other
         * than cryptographic keys.
         */
        DATA_ENCIPHERMENT (KeyUsage.keyEncipherment),

        /**
         * Use when the sender and receiver of the public key need to derive
         * the key without using encryption. This key can then can be used to
         * encrypt messages between the sender and receiver. Key agreement is
         * typically used with Diffie-Hellman ciphers.
         */
        KEY_AGREEMENT     (KeyUsage.keyAgreement),

        /**
         * Use when the subject public key is used to verify a signature on
         * certificates. This extension can be used only in CA certificates.
         */
        KEY_CERT_SIGN     (KeyUsage.keyCertSign),

        /**
         * Use when the subject public key is to verify a signature on
         * revocation information, such as a CRL.
         */
        CRL_SIGN          (KeyUsage.cRLSign),

        /**
         * Use only when key agreement is also enabled. This enables the
         * public key to be used only for enciphering data while performing
         * key agreement.
         */
        ENCIPHER_ONLY     (KeyUsage.encipherOnly),

        /**
         * Use only when key agreement is also enabled. This enables the
         * public key to be used only for deciphering data while performing
         * key agreement.
         */
        DECIPHER_ONLY     (KeyUsage.decipherOnly);

        private int usage;

        private StandardKeyUsage(int usage) {
            this.usage = usage;
        }

        private static int combine(Collection<? extends StandardKeyUsage> collection) {
            int usage = 0;
            for (StandardKeyUsage flag: collection) {
                usage |= flag.usage;
            }
            return usage;
        }

    }

    /**
     * An enumeration containing the possible <i>extended key usages</i>
     * supported by a {@link X509CertificateBuilder}.
     *
     * <p>Extended key usage further refines key usage extensions. An extended
     * key is either critical or non-critical. If the extension is critical,
     * the certificate must be used only for the indicated purpose or purposes.
     * If the certificate is used for another purpose, it is in violation of
     * the CA's policy.</p>
     *
     * <p>If the extension is non-critical, it indicates the intended purpose
     * or purposes of the key and may be used in finding the correct
     * key/certificate of an entity that has multiple keys/certificates.
     * The extension is then only an informational field and does not imply
     * that the CA restricts use of the key to the purpose indicated.
     * Nevertheless, applications that use certificates may require that a
     * particular purpose be indicated in order for the certificate to be
     * acceptable.</p>
     *
     * <p>If a certificate contains both a critical key usage field and a
     * critical extended key usage field, both fields must be processed
     * independently, and the certificate be used only for a purpose
     * consistent with both fields. If there is no purpose consistent with
     * both fields, the certificate must not be used for any purpose.</p>
     *
     * @see <a target="_blank" href="http://publib.boulder.ibm.com/infocenter/domhelp/v8r0/index.jsp?topic=%2Fcom.ibm.help.domino.admin.doc%2FDOC%2FH_KEY_USAGE_EXTENSIONS_FOR_INTERNET_CERTIFICATES_1521_OVER.html">IBM's reference</a>
     */
    public enum ExtendedKeyUsage {
        /** Any extended key usage */
        ANY              (KeyPurposeId.anyExtendedKeyUsage),
        /** TLS web server authentication. */
        SERVER_AUTH      (KeyPurposeId.id_kp_serverAuth),
        /** TLS web client authentication. */
        CLIENT_AUTH      (KeyPurposeId.id_kp_clientAuth),
        /** Sign (downloadable) executable code. */
        CODE_SIGNING     (KeyPurposeId.id_kp_codeSigning),
        /** Email protection. */
        EMAIL_PROTECTION (KeyPurposeId.id_kp_emailProtection),
        /** Timestamping. */
        TIME_STAMPING    (KeyPurposeId.id_kp_timeStamping),
        /** Sign OCSP <i>(Online Certificate Status Protocol)</i> responses. */
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

    /**
     * Standard <em>modes</em> for certificates.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Mode {
        /**
         * Client mode:
         * {@linkplain StandardKeyUsage#DIGITAL_SIGNATURE digital signature},
         * {@linkplain StandardKeyUsage#KEY_ENCIPHERMENT key encipherment} and
         * {@linkplain ExtendedKeyUsage#CLIENT_AUTH TLS web client authentication}.
         */
        CLIENT(new StandardKeyUsage[] { StandardKeyUsage.DIGITAL_SIGNATURE, StandardKeyUsage.KEY_ENCIPHERMENT },
               new ExtendedKeyUsage[] { ExtendedKeyUsage.CLIENT_AUTH }),

        /**
         * Server mode:
         * {@linkplain StandardKeyUsage#DIGITAL_SIGNATURE digital signature},
         * {@linkplain StandardKeyUsage#KEY_ENCIPHERMENT key encipherment} and
         * {@linkplain ExtendedKeyUsage#SERVER_AUTH TLS web server authentication}.
         */
        SERVER(new StandardKeyUsage[] { StandardKeyUsage.DIGITAL_SIGNATURE, StandardKeyUsage.KEY_ENCIPHERMENT },
               new ExtendedKeyUsage[] { ExtendedKeyUsage.SERVER_AUTH }),

        /**
         * Certificate Authority mode:
         * {@linkplain StandardKeyUsage#KEY_CERT_SIGN certificate signatures},
         * {@linkplain StandardKeyUsage#CRL_SIGN crl signatures},
         * {@linkplain ExtendedKeyUsage#OCSP_SIGNING OCSP response signing} and
         * will enable the <i>certificate authority</i> flag in the Standard
         * constraints of the certificate.
         */
        AUTHORITY(new StandardKeyUsage[] { StandardKeyUsage.KEY_CERT_SIGN, StandardKeyUsage.CRL_SIGN },
                  new ExtendedKeyUsage[] { ExtendedKeyUsage.OCSP_SIGNING });

        private Set<StandardKeyUsage> Standard;
        private Set<ExtendedKeyUsage> extended;

        private Mode(StandardKeyUsage[] Standard, ExtendedKeyUsage[] extended) {
            this.Standard = Standard.length == 0 ? Collections.<StandardKeyUsage>emptySet() : EnumSet.of(Standard[0], Standard);
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

    private final Set<StandardKeyUsage> standardKeyUsage = new HashSet<>();
    private final Set<ExtendedKeyUsage> extendedKeyUsage = new HashSet<>();
    private final List<GeneralName> alternativeNames = new ArrayList<>();
    private final Set<GeneralName> crlDistributionPoints = new HashSet<>();

    /* ====================================================================== */

    /**
     * Create a new {@link X509CertificateBuilder} with validity
     * {@linkplain #notBefore from} <i>now</i> and
     * {@linkplain #notAfter(long, TimeUnit) duration} of one year.
     */
    public X509CertificateBuilder() {
        this(null);
    }

    /**
     * Create a new {@link X509CertificateBuilder} in the specified
     * {@link Mode} with validity
     * {@linkplain #notBefore from} <i>now</i> and
     * {@linkplain #notAfter(long, TimeUnit) duration} of one year.
     */
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

    /**
     * Build the final {@link X509Certificate} instance.
     */
    public X509Certificate build() {
        if (subject == null) throw new IllegalStateException("Subject not specified");
        if (issuer == null) throw new IllegalStateException("Issuer not specified");
        if (serial == null) throw new IllegalStateException("Serial not specified");
        if (!notAfter.after(notBefore)) throw new IllegalStateException("Date \"not-after\" before or equal to \"not-before\"");
        if (issuerPrivateKey == null) throw new IllegalStateException("Issuer private key not specified");
        if (subjectPublicKey == null) throw new IllegalStateException("Sobject public key not specified");

        /* Standard subject public key and X500 names */
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

            /* Do we have Standard key usages? */
            if (!standardKeyUsage.isEmpty())
                certificateBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(StandardKeyUsage.combine(standardKeyUsage)));

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
            throw new IllegalStateException("Exception adding extensions", exception);
        }

        try {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(issuerPrivateKey);
            final X509CertificateHolder certificateHolder = certificateBuilder.build(signer);
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificateHolder.getEncoded()));
        } catch (OperatorCreationException exception) {
            throw new IllegalStateException("Unable to create certificate signature", exception);
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to generate certificate data", exception);
        } catch (CertificateException exception) {
            throw new IllegalStateException("Unable to generate certificate", exception);
        }
    }

    /* ====================================================================== */

    /**
     * Set the Standard {@link Mode} of this {@link X509CertificateBuilder}.
     *
     * <p>This will reset both {@linkplain #clearStandardKeyUsage() Standard}
     * and {@linkplain #clearExtendedKeyUsage() extended} key usage flags.
     */
    public X509CertificateBuilder mode(Mode mode) {
        clearStandardKeyUsage();
        clearExtendedKeyUsage();
        if (mode != null) {
            standardKeyUsage.addAll(mode.Standard);
            extendedKeyUsage.addAll(mode.extended);
        }
        this.mode = mode;
        return this;
    }

    /**
     * Clear all {@linkplain StandardKeyUsage standard key usage} flags.
     */
    public X509CertificateBuilder clearStandardKeyUsage() {
        standardKeyUsage.clear();
        return this;
    }

    /**
     * Add the specified {@linkplain StandardKeyUsage standard key usage} flags.
     */
    public X509CertificateBuilder standardKeyUsage(StandardKeyUsage... standardUsages) {
        standardKeyUsage.addAll(Arrays.asList(standardUsages));
        return this;
    }

    /**
     * Clear all {@linkplain ExtendedKeyUsage standard key usage} flags.
     */
    public X509CertificateBuilder clearExtendedKeyUsage() {
        extendedKeyUsage.clear();
        return this;
    }

    /**
     * Add the specified {@linkplain ExtendedKeyUsage standard key usage} flags.
     */
    public X509CertificateBuilder extendedKeyUsage(ExtendedKeyUsage... extendedUsages) {
        extendedKeyUsage.addAll(Arrays.asList(extendedUsages));
        return this;
    }

    /* ====================================================================== */

    /**
     * Set the certificate's subject {@linkplain X500Principal principal}.
     */
    public X509CertificateBuilder subject(X500Principal subject) {
        if (subject == null) throw new NullPointerException("Null subject");
        this.subject = subject;
        return this;
    }

    /**
     * Set the certificate's subject {@linkplain X500Principal principal} by
     * {@linkplain X500Principal#X500Principal(String) parsing} a string.
     */
    public X509CertificateBuilder subject(String subject) {
        if (subject == null) throw new NullPointerException("Null subject");
        return this.subject(new X500Principal(subject));
    }

    /* ====================================================================== */

    /**
     * Set the {@linkplain X509Certificate certificate} of the authority
     * issuing the certificate.
     *
     * <p>This method will set the issuer's
     * {@linkplain #issuer(X500Principal) principal},
     * {@linkplain #issuerPublicKey(Key) public key}
     * and will attempt to copy the issuer's
     * {@linkplain #crlDistributionPoint(URI) CRL distribution points}
     * in the issued certificate.</p>
     */
    public X509CertificateBuilder issuer(X509Certificate issuer) {
        if (issuer == null) throw new NullPointerException("Null issuer");
        this.issuer(issuer.getSubjectX500Principal());
        issuerPublicKey(issuer.getPublicKey());

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

    /**
     * Set the certificate's issuer {@linkplain X500Principal principal}.
     */
    public X509CertificateBuilder issuer(X500Principal issuer) {
        if (issuer == null) throw new NullPointerException("Null issuer");
        this.issuer = issuer;
        return this;
    }

    /**
     * Set the certificate's issuer {@linkplain X500Principal principal} by
     * {@linkplain X500Principal#X500Principal(String) parsing} a string.
     */
    public X509CertificateBuilder issuer(String issuer) {
        if (issuer == null) throw new NullPointerException("Null issuer");
        return this.issuer(new X500Principal(issuer));
    }

    /* ====================================================================== */

    /**
     * Set the serial number of the issued certificate.
     */
    public X509CertificateBuilder serial(BigInteger serial) {
        if (serial == null) throw new NullPointerException("Null serial");
        if (serial.signum() != 1) throw new NullPointerException("Serial must be positive");
        this.serial = serial;
        return this;
    }

    /**
     * Set the serial number of the issued certificate.
     */
    public X509CertificateBuilder serial(long serial) {
        return this.serial(BigInteger.valueOf(serial));
    }

    /* ====================================================================== */

    /**
     * Set the <em>not-valid-before</em> date of the issued certificate.
     */
    public X509CertificateBuilder notBefore(Date notBefore) {
        if (notBefore == null) throw new NullPointerException("Null \"not-before\" date");
        this.notBefore = notBefore;
        return this;
    }

    /**
     * Set the <em>not-valid-before</em> date of the issued certificate (in
     * milliseconds from the Epoch).
     */
    public X509CertificateBuilder notBefore(long notBefore) {
        return this.notBefore(new Date(notBefore));
    }

    /* ====================================================================== */

    /**
     * Set the <em>not-valid-after</em> date of the issued certificate.
     */
    public X509CertificateBuilder notAfter(Date notAfter) {
        if (notAfter == null) throw new NullPointerException("Null \"not-after\" date");
        this.notAfter = notAfter;
        return this;
    }

    /**
     * Set the <em>not-valid-after</em> date of the issued certificate (in
     * milliseconds from the Epoch).
     */
    public X509CertificateBuilder notAfter(long notAfter) {
        return this.notAfter(new Date(notAfter));
    }

    /**
     * Set the <em>not-valid-after</em> date of the issued certificate deriving
     * it from the <em>{@linkplain #notBefore(Date) not-valid-before}</em> date
     * and, a duration and {@linkplain TimeUnit time unit}.
     *
     * <p>Obviously the <em>{@linkplain #notBefore(Date) not-valid-before}</em>
     * date must be set <b>prior</b> to calling this method.</p>
     */
    public X509CertificateBuilder notAfter(long duration, TimeUnit unit) {
        if (notBefore == null) throw new IllegalStateException("Date \"not-before\" not yet specified");
        return this.notAfter(notBefore.getTime() + MILLISECONDS.convert(duration, unit));
    }

    /* ====================================================================== */

    /**
     * Set the issuer private key that will be used to sign the certificate.
     */
    public X509CertificateBuilder issuerPrivateKey(Key key) {
        if (key == null) throw new NullPointerException("Null issuer private key");
        try {
            issuerPrivateKey = (PrivateKey) key;
            return this;
        } catch (ClassCastException exception) {
            throw new IllegalArgumentException("Key " + key.getClass().getName() + " is not a private key");
        }
    }

    /**
     * Set the (optional) issuer public key that will be included in the
     * generated certificate.
     */
    public X509CertificateBuilder issuerPublicKey(Key key) {
        if (key == null) throw new NullPointerException("Null issuer public key");
        try {
            issuerPublicKey = (PublicKey) key;
            return this;
        } catch (ClassCastException exception) {
            throw new IllegalArgumentException("Key " + key.getClass().getName() + " is not a public key");
        }
    }

    /**
     * Set both the issuer {@linkplain #issuerPrivateKey(Key) private} and
     * {@linkplain #issuerPublicKey(Key) public} keys from a {@link KeyPair}.
     */
    public X509CertificateBuilder issuerKeyPair(KeyPair keyPair) {
        if (keyPair == null) throw new NullPointerException("Null issuer key pair");
        issuerPrivateKey(keyPair.getPrivate());
        issuerPublicKey(keyPair.getPublic());
        return this;
    }

    /**
     * Set the subject public key that will be included in the generated
     * certificate.
     */
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

    /**
     * Clear all alternative names that were set up until now.
     */
    public X509CertificateBuilder clearAlternativeNames() {
        alternativeNames.clear();
        return this;
    }

    /**
     * Add an alternative name in the form of an email address to the
     * generated certificate.
     */
    public X509CertificateBuilder alternativeNameEmail(String email) {
        if (email == null) throw new NullPointerException("Null email");
        alternativeNames.add(new GeneralName(GeneralName.rfc822Name, email));
        return this;
    }

    /**
     * Add an alternative name in the form of a DNS name (a host name) to the
     * generated certificate.
     */
    public X509CertificateBuilder alternativeNameDNS(String dnsName) {
        if (dnsName == null) throw new NullPointerException("Null DNS name");
        alternativeNames.add(new GeneralName(GeneralName.dNSName, dnsName));
        return this;
    }

    /**
     * Add an alternative name in the form of an {@link URI} to the
     * generated certificate.
     */
    public X509CertificateBuilder alternativeNameURI(String uri) {
        if (uri == null) throw new NullPointerException("Null URI");
        return alternativeNameURI(URI.create(uri));
    }

    /**
     * Add an alternative name in the form of an {@link URI} to the
     * generated certificate.
     */
    public X509CertificateBuilder alternativeNameURI(URL url) {
        if (url == null) throw new NullPointerException("Null URL");
        try {
            return alternativeNameURI(url.toURI());
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid URI " + url.toString(), exception);
        }
    }

    /**
     * Add an alternative name in the form of an {@link URI} to the
     * generated certificate.
     */
    public X509CertificateBuilder alternativeNameURI(URI uri) {
        if (uri == null) throw new NullPointerException("Null URI");
        final String string = uri.toASCIIString();
        alternativeNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, string));
        return this;
    }

    /**
     * Add an alternative name in the form of an IP address to the
     * generated certificate.
     */
    public X509CertificateBuilder alternativeNameIPAddress(InetAddress address) {
        if (address == null) throw new NullPointerException("Null address");
        return this.alternativeNameIPAddress(address.getHostAddress());
    }

    /**
     * Add an alternative name in the form of an IP address to the
     * generated certificate.
     *
     * <p>Both IPv4 and IPv6 are supported, and network masks can be specified
     * after a slash character in the string.</p>
     */
    public X509CertificateBuilder alternativeNameIPAddress(String address) {
        if (address == null) throw new NullPointerException("Null address");
        alternativeNames.add(new GeneralName(GeneralName.iPAddress, address));
        return this;
    }

    /* ====================================================================== */

    /**
     * Clear all CRL distribution points that were set up until now.
     */
    public X509CertificateBuilder clearCRLDistributionPoints() {
        crlDistributionPoints.clear();
        return this;
    }

    /**
     * Add a new CRL distribution point to the generated certificate.
     */
    public X509CertificateBuilder crlDistributionPoint(String uri) {
        if (uri == null) throw new NullPointerException("Null CRL distribution point");
        return this.crlDistributionPoint(URI.create(uri));
    }

    /**
     * Add a new CRL distribution point to the generated certificate.
     */
    public X509CertificateBuilder crlDistributionPoint(URL url) {
        if (url == null) throw new NullPointerException("Null CRL distribution point");
        try {
            return this.crlDistributionPoint(url.toURI());
        } catch (URISyntaxException exception) {
            throw new IllegalArgumentException("Invalid URI " + url.toString(), exception);
        }
    }

    /**
     * Add a new CRL distribution point to the generated certificate.
     */
    public X509CertificateBuilder crlDistributionPoint(URI uri) {
        if (uri == null) throw new NullPointerException("Null CRL distribution point");
        final String string = uri.toASCIIString();
        crlDistributionPoints.add(new GeneralName(GeneralName.uniformResourceIdentifier, string));
        return this;
    }

    /* ====================================================================== */

    /**
     * Set up this {@link X509CertificateBuilder} to prepare a self-signed
     * certificate.
     *
     * <p>This method will set up the current builder in
     * {@linkplain Mode#SERVER server mode}, use the same
     * {@linkplain X500Principal principal} both for the
     * {@linkplain #issuer(X500Principal) issuer} and
     * {@linkplain #issuer(X500Principal) subject} and
     * will use the various needed keys from the specified {@link KeyPair},
     * while the serial number will be set to the {@linkplain CRC32 CRC32 hash}
     * of the {@linkplain X500Principal#getEncoded() encoded principal}.</p>
     */
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

    /**
     * Set up this {@link X509CertificateBuilder} to prepare a self-signed
     * certificate.
     *
     * @see #selfSigned(X500Principal, KeyPair)
     */
    public X509CertificateBuilder selfSigned(String principal, KeyPair keyPair) {
        if (subject == null) throw new NullPointerException("Null subject");
        return this.selfSigned(new X500Principal(principal), keyPair);
    }

}
