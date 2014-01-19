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

import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.crypto.hash.MD;

/**
 * A {@link KDF} using the same (simple) key derivation algorithm used
 * by the <a href="http://www.openssl.org/">OpenSSL</a> library.
 *
 * See <a href="http://www.openssl.org/docs/crypto/EVP_BytesToKey.html">here</a> and
 * <a href="http://stackoverflow.com/questions/9488919/openssl-password-to-key">here</a>
 * for some pointers on how OpenSSL's KDF works.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public class OpenSSLKDF extends AbstractKDF {

    /**
     * Create an {@link OpenSSLKDF} producing keys of the specified length.
     */
    public OpenSSLKDF(int derivedKeyLength) {
        super(derivedKeyLength);
    }

    @Override
    protected void computeKey(byte[] password, byte[] salt, byte[] output, int offset) {
        final MD digest = Hash.MD5.digest();
        final int length = digest.getHashLength();

        final byte[] buffer = new  byte[length];
        while (true) {

            /* Add the key and salt */
            digest.update(password);
            digest.update(salt, 0, salt.length > 8? 8: salt.length);

            /* Calculate the digest and copy it in the result buffer */
            digest.finish(buffer, 0);
            final int x = output.length - offset;
            final int needed = x > length ? length : x;
            System.arraycopy(buffer, 0, output, offset, needed);

            /* Need more data? */
            if ((offset += length) >= output.length) break;

            /* Prepare for the next iteration */
            digest.update(buffer);
        }
    }

}
