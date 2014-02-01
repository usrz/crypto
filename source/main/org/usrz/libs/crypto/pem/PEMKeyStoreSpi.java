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

import static org.usrz.libs.crypto.codecs.CharsetCodec.UTF8;
import static org.usrz.libs.crypto.pem.PEMEntry.Type.X509_CERTIFICATE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.usrz.libs.crypto.codecs.CharsetCodec;
import org.usrz.libs.crypto.pem.PEMEntry.Type;

public class PEMKeyStoreSpi extends KeyStoreSpi {

    private static final Logger logger = Logger.getLogger(PEMKeyStoreSpi.class.getName());

    private final ConcurrentHashMap<String, PEMEntry<?>> entries;
    private final ConcurrentHashMap<X509Certificate, String> certificateAliases;
    private final ConcurrentHashMap<X500Principal, X509Certificate> certificates;

    public PEMKeyStoreSpi() {
        entries = new ConcurrentHashMap<>();
        certificates = new ConcurrentHashMap<>();
        certificateAliases = new ConcurrentHashMap<>();
    }

    /* ====================================================================== *
     * LOADING                                                                *
     * ====================================================================== */

    @Override
    public void engineLoad(InputStream stream, char[] password)
    throws IOException, NoSuchAlgorithmException, CertificateException {
        final byte[] key = password == null ? null : new String(password).getBytes(UTF8);

        final List<PEMEntry<?>> entries;
        try {
            entries = new PEMReader(stream, CharsetCodec.ASCII).read();
        } catch (PEMException exception) {
            throw new IOException("Exception reading PEM data", exception);
        }

        for (PEMEntry<?> entry: entries) {
            if (logger.isLoggable(Level.FINER)) logger.finer("Found " + entry);
            final String alias = entry.getAlias();
            this.entries.put(alias, entry);

            /* If this is a certificate, just add it in our other tables */
            if (entry.getType() == Type.X509_CERTIFICATE) try {
                final X509Certificate certificate = ((PEMX509CertificateEntry) entry).get(key);
                certificates.put(certificate.getSubjectX500Principal(), certificate);
                certificateAliases.put(certificate, alias);

            } catch (NoSuchAlgorithmException|CertificateException exception) {
                throw exception;
            } catch (GeneralSecurityException exception) {
                throw new CertificateException("Exception getting certificate", exception);
            }
        }
    }

    /* ====================================================================== *
     * KEYSTORE SUPPORTED METHODS                                             *
     * ====================================================================== */

    @Override
    public Date engineGetCreationDate(String alias) {
        /* Return the epoch if the entry exists, PEM doesn't store dates */
        return entries.containsKey(alias) ? new Date(0) : null;
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return entries.containsKey(alias);
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(entries.keySet());
    }

    @Override
    public int engineSize() {
        return entries.size();
    }

    @Override
    public String engineGetCertificateAlias(Certificate certificate) {
        return certificateAliases.get(certificate);
    }

    /* ====================================================================== */

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        final PEMEntry<?> entry = entries.get(alias);
        if (entry == null) return false;
        switch (entry.getType()) {
            case RSA_PRIVATE_KEY:  return false;
            case RSA_PUBLIC_KEY:   return false;
            case X509_CERTIFICATE: return true;
        }
        logger.warning("Entry " + entry + " has unknown type " + entry.getType());
        return false;
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        final PEMEntry<?> entry = entries.get(alias);
        if (entry == null) return false;
        switch (entry.getType()) {
            case RSA_PRIVATE_KEY:  return true;
            case RSA_PUBLIC_KEY:   return true;
            case X509_CERTIFICATE: return false;
        }
        logger.warning("Entry " + entry + " has unknown type " + entry.getType());
        return false;
    }

    /* ====================================================================== */

    @Override
    public X509Certificate engineGetCertificate(String alias) {
        final PEMEntry<?> entry = entries.get(alias);
        if (entry == null) return null;
        if (entry.getType() == X509_CERTIFICATE) try {
            return ((PEMX509CertificateEntry) entry).get();
        } catch (Exception exception) {
            logger.log(Level.WARNING, "Entry " + entry + " could not be accessed", exception);
        }
        return null;
    }

    @Override
    public Key engineGetKey(String alias, char[] password)
    throws NoSuchAlgorithmException, UnrecoverableKeyException {
        final PEMEntry<?> entry = entries.get(alias);
        if (entry == null) return null;

        final byte[] key = password == null ? null : new String(password).getBytes(UTF8);
        try {
            switch (entry.getType()) {
                case RSA_PRIVATE_KEY:  return ((PEMRSAPrivateKeyEntry) entry).get(key);
                case RSA_PUBLIC_KEY:   return ((PEMRSAPublicKeyEntry) entry).get(key);
                case X509_CERTIFICATE: return null;
            }
            logger.warning("Entry " + entry + " has unknown type " + entry.getType());
            return null;
        } catch (Exception exception) {
            final Exception wrapper = new UnrecoverableKeyException("Key " + alias + " could not be recovered");
            throw (UnrecoverableKeyException) wrapper.initCause(exception);
        }
    }

    /* ====================================================================== */

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {

        /* Our certificate */
        X509Certificate certificate = engineGetCertificate(alias);
        if (certificate == null) return null;

        /* Start building a chain */
        if (logger.isLoggable(Level.FINER))
            logger.finer("Building chain for " + certificate.getSubjectX500Principal());

        final List<X509Certificate> chain = new ArrayList<>();
        chain.add(certificate);

        /* Look for the issuer */
        X509Certificate issuer = certificates.get(certificate.getIssuerX500Principal());
        while ((issuer != null) && (!issuer.equals(certificate))) {

            if (logger.isLoggable(Level.FINER))
                logger.finer("Issuer for " + certificate.getSubjectX500Principal() + " is " + issuer.getSubjectX500Principal());

            try {
                certificate.verify(issuer.getPublicKey());
            } catch (Exception exception) {
                final String message = "Unable to verify certificate " + certificate.getSubjectX500Principal() +
                                       " with issuer " + issuer.getSubjectX500Principal();
                logger.log(Level.WARNING, message, exception);
                throw new IllegalStateException(message, exception);
            }

            chain.add(issuer);
            certificate = issuer;
            issuer = certificates.get(certificate.getIssuerX500Principal());
        }

        /* The chain is built */
        return chain.toArray(new X509Certificate[chain.size()]);
    }

    /* ====================================================================== *
     * UNSUPPORTED METHODS                                                    *
     * ====================================================================== */

    @Override
    public void engineStore(OutputStream stream, char[] password)
    throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new IOException("PEM file can not be saved");
    }

    @Override
    public void engineDeleteEntry(String alias)
    throws KeyStoreException {
        throw new KeyStoreException("PEM key store is read-only");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
    throws KeyStoreException {
        throw new KeyStoreException("PEM key store is read-only");
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
    throws KeyStoreException {
        throw new KeyStoreException("PEM key store is read-only");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert)
    throws KeyStoreException {
        throw new KeyStoreException("PEM key store is read-only");
    }

}
