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
package org.usrz.libs.crypto.kdf;

import static org.usrz.libs.crypto.hash.Hash.MD5;
import static org.usrz.libs.crypto.hash.Hash.SHA1;
import static org.usrz.libs.crypto.hash.Hash.SHA256;

import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.utils.Check;

/**
 * The {@link KDF} interface defines a component capable of derivating a
 * key from a password and <i>salt</i>.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Key_derivation_function">Key
 *      derivation functions</a>
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public interface KDF {

    /**
     * All known {@link KDF} functions.
     *
     * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
     */
    public enum Function {

        /**
         * OpenSSL's own (internal) KDF:
         * defaults to {@link Hash#MD5 MD5} hash,
         * 16 bytes (128 bits) of derived key length.
         */
        OPENSSL(MD5),
        /**
         * Password-Based Key Derivation Function 2:
         * defaults to {@link Hash#SHA1 SHA1} hash,
         * 20 bytes (160 bits) of derived key length.
         */
        PBKDF2(SHA1),
        /**
         * <i>Colin Percival</i>'s SCrypt key derivation function:
         * defaults to {@link Hash#SHA256 SHA256} hash,
         * 32 bytes (256 bits) of derived key length.
         */
        SCRYPT(SHA256);

        /* The default hash */
        private final Hash hash;

        /* Construct */
        private Function(Hash hash) {
            this.hash = Check.notNull(hash, "Null hash");
        }

        /**
         * Return the default kind of {@link Hash} used by {@link KDF}s of
         * this {@link Function}.
         */
        public Hash getDefaultHash() {
            return hash;
        }
    };

    /* ====================================================================== */

    /**
     * Return the {@link KDFSpec} associated with this instance.
     */
    public KDFSpec getKDFSpec();

    /**
     * Derive a key from the specified password and <i>salt</i>, and return it
     * into a new <code>byte[]</code>.
     *
     * @throws NullPointerException If password or <i>salt</i> were <b>null</b>.
     */
    public byte[] deriveKey(byte[] password, byte[] salt)
    throws NullPointerException;

    /**
     * Derive a key from the specified password and <i>salt</i> and write in the
     * specified <code>byte[]</code> at the specified position.
     *
     * @throws NullPointerException If password, <i>salt</i> or output buffer
     *                              were <b>null</b>.
     * @throws IllegalArgumentException If the buffer was not big enough.
     */
    public void deriveKey(byte[] password, byte[] salt, byte[] output, int offset)
    throws NullPointerException, IllegalArgumentException;

}
