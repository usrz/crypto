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
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.List;

/**
 * A utility class for managing signatures in <code>PKCS7</code> using
 * <i>SHA-1</i> for digest and <i>RSA</i> as encryption.
 *
 * @see <a href="http://tools.ietf.org/html/rfc2315">RFC-2315</a>
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class PKCS7 {


    private static final sun.security.x509.AlgorithmId DIGEST_ALGORITHM =     new sun.security.x509.AlgorithmId(sun.security.x509.AlgorithmId.SHA_oid);
    private static final sun.security.x509.AlgorithmId SIGNATURE_ALGORITHM =  new sun.security.x509.AlgorithmId(sun.security.x509.AlgorithmId.sha1WithRSAEncryption_oid);
    private static final sun.security.x509.AlgorithmId ENCRYPTION_ALGORITHM = new sun.security.x509.AlgorithmId(sun.security.x509.AlgorithmId.RSAEncryption_oid);

    private static final sun.security.x509.AlgorithmId[] DIGEST_ALGORITHMS = { DIGEST_ALGORITHM };

    private static final sun.security.util.ObjectIdentifier CONTENT_TYPE_OID =   sun.security.pkcs.PKCS9Attribute.CONTENT_TYPE_OID;
    private static final sun.security.util.ObjectIdentifier MESSAGE_DIGEST_OID = sun.security.pkcs.PKCS9Attribute.MESSAGE_DIGEST_OID;
    private static final sun.security.util.ObjectIdentifier SIGNING_TIME_OID =   sun.security.pkcs.PKCS9Attribute.SIGNING_TIME_OID;
    private static final sun.security.util.ObjectIdentifier DATA_OID =   sun.security.pkcs.ContentInfo.DATA_OID;

    /* ====================================================================== */

    private PKCS7() {
        throw new IllegalStateException("Do not instantiate");
    }

    /* ====================================================================== */

    /**
     * Prepare a detached <code>PKCS7</code> signature using <i>SHA-1</i> for
     * digest and <i>RSA</i> as encryption.
     *
     * @param privateKey The private key to use for signing
     * @param certificate The certificate associated with the private key.
     * @param authorities An optional list of certificate authorities to include.
     * @param data The binary data to sign.
     * @return The <code>PKCS7</code> as a byte array.
     * @throws NoSuchAlgorithmException If either <i>SHA-1</i> or <i>RSA</i>
     *                                  were not supported.
     * @throws InvalidKeyException If there was a problem with the key.
     * @throws SignatureException If there was a problem generating the signature.
     */
    public static byte[] sign(final RSAPrivateKey privateKey,
                              final X509Certificate certificate,
                              final List<X509Certificate> authorities,
                              final byte[] data)
    throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        /* Validate parameters */
        if (data == null) throw new NullPointerException("Null data");
        if (privateKey == null) throw new NullPointerException("Null key");
        if (certificate == null) throw new NullPointerException("Null certificate");

        /* Check the

        /* Prepare the signature of our data */
        final byte[] digest = MessageDigest.getInstance(DIGEST_ALGORITHM.getName()).digest(data);

        /* Prepare the set of our authenticated attributes */
        final sun.security.pkcs.PKCS9Attributes attributes;
        final byte[] attributesData;
        try {
            attributes = new sun.security.pkcs.PKCS9Attributes(
                        new sun.security.pkcs.PKCS9Attribute[] {
                            new sun.security.pkcs.PKCS9Attribute(CONTENT_TYPE_OID, DATA_OID),
                            new sun.security.pkcs.PKCS9Attribute(MESSAGE_DIGEST_OID, digest),
                            new sun.security.pkcs.PKCS9Attribute(SIGNING_TIME_OID, new Date())
                        });
            attributesData = attributes.getDerEncoding();
        } catch (IOException exception) {
            throw new IllegalStateException("I/O error without I/O", exception);
        }

        /* Prepare our signature */
        final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM.getName());
        signature.initSign(privateKey);
        signature.update(attributesData);

        /* Prepare our content info (no content "null", detached signature) */
        final sun.security.pkcs.ContentInfo contentInfo =
                new sun.security.pkcs.ContentInfo(
                        sun.security.pkcs.ContentInfo.DATA_OID,
                        null);

        /* Add up all our certificates in a single array */
        final int certificatesNumber = authorities == null ? 1 : authorities.size() + 1;
        final X509Certificate[] certificates = new X509Certificate[certificatesNumber];
        if (authorities != null) for (int x = 0; x < authorities.size(); x ++)
            certificates[x + 1] = authorities.get(x);
        certificates[0] = certificate;

        /* Create our signer information */
        final sun.security.pkcs.SignerInfo[] signerInfo = {
                new sun.security.pkcs.SignerInfo(
                        (sun.security.x509.X500Name) certificate.getIssuerDN(),
                        certificate.getSerialNumber(),
                        DIGEST_ALGORITHM,
                        attributes,
                        ENCRYPTION_ALGORITHM,
                        signature.sign(),
                        null)}; // no unauthenticated attributes

        /* Encode the signature in PKCS7 and return it */
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
            new sun.security.pkcs.PKCS7(DIGEST_ALGORITHMS,
                                        contentInfo,
                                        certificates,
                                        signerInfo).encodeSignedData(bytes);
            return bytes.toByteArray();
        } catch (IOException exception) {
            throw new IllegalStateException("I/O error without I/O", exception);
        }
    }
}
