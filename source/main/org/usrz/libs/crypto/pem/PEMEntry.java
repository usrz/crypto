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

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.usrz.libs.crypto.kdf.OpenSSLKDF;

/**
 * An abstract class representing an entry in a <i>PEM-encoded</i> file.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 * @param <T> The Java type of the object contained in this entry.
 */
public abstract class PEMEntry<T> {

    /**
     * A class defining the various types of a {@linkplain PEMEntry PEM entry}.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Type {

        /**
         * The {@link Type} identifying a <em>RSA private key</em>.
         *
         * @see PEMRSAPrivateKeyEntry
         */
        RSA_PRIVATE_KEY,

        /**
         * The {@link Type} identifying a <em>RSA public key</em>.
         *
         * @see PEMRSAPublicKeyEntry
         */
        RSA_PUBLIC_KEY,

        /**
         * The {@link Type} identifying an <em>X.509 certificate</em>.
         *
         * @see PEMX509CertificateEntry
         */
        X509_CERTIFICATE

    }

    /* ================================================================== */

    /**
     * An enumeration defining the various types of encryption allowable for a
     * {@linkplain PEMEntry PEM entry}.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Encryption {

        /** <em>DES</em> encryption with 64 bits of key length. */
        DES_CBC     ("DES/CBC/PKCS5Padding",    "DES",     8),
        /** <em>DES/EDE3 <small>(Triple-DES)</small></em> encryption with 192 bits of key length. */
        DES_EDE3_CBC("DESede/CBC/PKCS5Padding", "DESede", 24),
        /** <em>AES</em> encryption with 128 bits of key length. */
        AES_128_CBC ("AES/CBC/PKCS5Padding",    "AES",    16),
        /** <em>AES</em> encryption with 192 bits of key length. */
        AES_192_CBC ("AES/CBC/PKCS5Padding",    "AES",    24),
        /** <em>AES</em> encryption with 256 bits of key length. */
        AES_256_CBC ("AES/CBC/PKCS5Padding",    "AES",    32);

        private final String cipherType;
        private final String keyType;
        private final int keyLength;

        private Encryption(String cipherType, String keyType, int keyLength) {
            this.cipherType = cipherType;
            this.keyType = keyType;
            this.keyLength = keyLength;
        }

        /* ================================================================== */

        /**
         * Return a value of this <i>enum</i> by normalizing the encryption
         * type specified in PEM files by OpenSSL.
         *
         * @see #valueOf(String)
         */
        public static Encryption normalizedValueOf(final String value) {
            return valueOf(value.toUpperCase().replace('-', '_'));
        }

        /* ================================================================== */

        /**
         * Return the cipher type as a {@link String}.
         */
        public String getCipherType() {
            return cipherType;
        }

        /**
         * Return the key type as a {@link String}.
         */
        public String getKeyType() {
            return keyType;
        }

        /**
         * Return the key length.
         */
        public int getKeyLength() {
            return keyLength;
        }

        /* ================================================================== */

        /**
         * Create a new {@link SecretKeySpec} from a password and salt which
         * can be used to decrypt data with this algorithm.
         */
        public SecretKeySpec newSecretKeySpec(byte[] password, byte[] salt) {
            /* Derive the encryption key MD5(key+salt) */
            final byte[] key =  new OpenSSLKDF(keyLength).deriveKey(password, salt);
            return new SecretKeySpec(key, 0, keyLength, keyType);
        }

        /**
         * Create a new <em>uninitialized</em> {@link Cipher} to decrypt the entry.
         */
        public Cipher newCipher()
        throws NoSuchAlgorithmException, NoSuchPaddingException {
            try {
                return Cipher.getInstance(cipherType);
            } catch (NoSuchAlgorithmException exception) {
                throw new NoSuchAlgorithmException("Algorithm \"" + cipherType + "\" for \"" + name() + "\" unsupported", exception);
            } catch (NoSuchPaddingException exception) {
                final Throwable throwable = new NoSuchPaddingException("Padding \"" + cipherType + "\" for \"" + name() + "\" unsupported");
                throw (NoSuchPaddingException) throwable.initCause(exception);
            }
        }

        /**
         * Create a <i>fully initialized</i> new {@link Cipher} to decrypt the
         * entry, initialized with a password and salt.
         */
        public Cipher newCipher(byte[] password, byte[] salt)
        throws NoSuchAlgorithmException, NoSuchPaddingException,
               InvalidKeyException, InvalidAlgorithmParameterException {

            /* Our cipher instance */
            final Cipher cipher = this.newCipher();

            /* Prepare our secret key spec and intialization vector spec */
            final SecretKeySpec secretKeySpec = newSecretKeySpec(password, salt);
            final IvParameterSpec ivectorSpecv = new IvParameterSpec(salt);

            /* Initialize our Cipher and return it */
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivectorSpecv);
            return cipher;
        }

        /**
         * Decrypt the specified data according to this algorithm, using the
         * given password and salt.
         */
        public byte[] decrypt(byte[] password, byte[] salt, byte[] data)
        throws InvalidKeyException, IllegalBlockSizeException,
               BadPaddingException, NoSuchAlgorithmException,
               NoSuchPaddingException, InvalidAlgorithmParameterException {
            return this.newCipher(password, salt).doFinal(data);
        }
    }

    /* ====================================================================== */

    /** A {@link KeyFactory} initialized with the <i>RSA</i> algorithm. */
    protected static final KeyFactory RSA_KEY_FACTORY;
    /** A {@link CertificateFactory} for X.509 certificates. */
    protected static final CertificateFactory CERTIFICATE_FACTORY;

    /* Initialize the RSA key factory and X.509 certificate factory */
    static {
        try {
            RSA_KEY_FACTORY = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException exception) {
            final Error error = new InternalError("RSA key factory unsupported");
            throw (InternalError) error.initCause(exception);
        }

        try {
            CERTIFICATE_FACTORY = CertificateFactory.getInstance("X.509");
        } catch (CertificateException exception) {
            final Error error = new InternalError("X.509 certificate factory unsupported");
            throw (InternalError) error.initCause(exception);
        }

    }

    /* ====================================================================== */

    private final Type type;
    private final Encryption encryption;
    private final byte[] data;
    private final byte[] salt;

    PEMEntry(Type type, byte[] data, byte[] salt, Encryption encryption) {
        if (type == null) throw new NullPointerException("Null type");
        if (data == null) throw new NullPointerException("Null data");

        if ((salt == null) && (encryption != null)) {
            throw new IllegalStateException("Encryption specified with no salt");
        } else if ((salt != null) && (encryption == null)) {
            throw new IllegalStateException("Salt specified with no encryption");
        }

        this.type = type;
        this.data = data;
        this.salt = salt;
        this.encryption = encryption;
    }

    /* ====================================================================== */

    /**
     * Return the {@link Type} of this {@linkplain PEMEntry entry}.
     */
    public final Type getType() {
        return type;
    }

    /**
     * Checks whether this {@linkplain PEMEntry entry} is encrypted or not.
     */
    public final boolean isEncrypted() {
        return encryption != null;
    }

    /**
     * Return the value of this unencrypted {@linkplain PEMEntry entry} as a
     * Java object.
     */
    public final T get()
    throws GeneralSecurityException {
        return get(null);
    }

    /**
     * Return the value of this {@linkplain PEMEntry entry} as a Java object.
     *
     * <p>If this entry {@link #isEncrypted() is encrypted}, a password
     * <b>must</b> specified, if not, it <b>must</b> be <b>null</b>.
     */
    public final T get(byte[] password)
    throws GeneralSecurityException {
        if (encryption != null) {
            if (password == null) {
                throw new InvalidKeyException("Password required for encrypted entries");
            } else {
                return doGet(encryption.decrypt(password, salt, this.data));
            }
        } else {
            return doGet(data);
        }

    }

    /**
     * Concrete implementations of the {@link PEMEntry} class must implement
     * this method to transform the specified data (unencrypted) to a proper
     * Java object.
     */
    protected abstract T doGet(byte[] data)
    throws GeneralSecurityException;

}
