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

import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.usrz.libs.crypto.hash.Hash;

/**
 * A utility class for managing signatures in <code>PKCS7</code>..
 *
 * @see <a href="http://tools.ietf.org/html/rfc2315">RFC-2315</a>
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class PKCS7 {

    private PKCS7() {
        throw new IllegalStateException("Do not instantiate");
    }

    /* ====================================================================== */

    /**
     * Prepare a detached <code>PKCS7</code> signature using <i>SHA-1</i> for
     * digest.
     *
     * @param privateKey The private key to use for signing
     * @param certificate The certificate associated with the private key.
     * @param authorities An optional list of certificate authorities to include.
     * @param data The binary data to sign.
     * @return The <code>PKCS7</code> as a byte array.
     * @throws SignatureException If there was a problem generating the signature.
     */
    public static byte[] sign(final PrivateKey privateKey,
                              final X509Certificate certificate,
                              final List<X509Certificate> authorities,
                              final byte[] data)
    throws SignatureException {
        return sign(privateKey, certificate, authorities, Hash.SHA1, data);
    }

    /**
     * Prepare a detached <code>PKCS7</code> signature.
     *
     * @param privateKey The private key to use for signing
     * @param certificate The certificate associated with the private key.
     * @param authorities An optional list of certificate authorities to include.
     * @param data The {@linkplain Hash hashing algorithm} to use for signing.
     * @param data The binary data to sign.
     * @return The <code>PKCS7</code> as a byte array.
     * @throws SignatureException If there was a problem generating the signature.
     */
    public static byte[] sign(final PrivateKey privateKey,
                              final X509Certificate certificate,
                              final List<X509Certificate> authorities,
                              final Hash hash, final byte[] data)
    throws SignatureException {
        try {
            final String signatureAlgorithm = CryptoUtils.getSignatureAlgorithm(privateKey, hash);
            final ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);

            final CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

            generator.addSignerInfoGenerator(
                    new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                        .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator())
                        .build(signer, certificate));

            final Set<Certificate> certificates = new HashSet<>();
            if (authorities != null) {
                for (Certificate authority: authorities) certificates.add(authority);
            }
            certificates.add(certificate);
            generator.addCertificates(new JcaCertStore(certificates));

            final CMSTypedData cmsData = new CMSProcessableByteArray(data);
            final CMSSignedData signeddata = generator.generate(cmsData, false);
            return signeddata.getEncoded();
        } catch (Exception exception) {
            throw new SignatureException("Signature could not be generated", exception);
        }
    }
}
