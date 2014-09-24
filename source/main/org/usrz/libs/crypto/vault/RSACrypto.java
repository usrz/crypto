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
package org.usrz.libs.crypto.vault;

import static org.usrz.libs.crypto.vault.Crypto.Algorithm.RSA;
import static org.usrz.libs.utils.Check.notNull;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.security.auth.DestroyFailedException;

import org.usrz.libs.logging.Log;

public class RSACrypto implements Crypto {

    private static final Log log = new Log(RSACrypto.class);

    private final Object lock = new Object();
    private final SecureRandom random;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    /* ====================================================================== */

    public RSACrypto(RSAPrivateKey privateKey) {
        this(new SecureRandom(), privateKey, null);
    }

    public RSACrypto(RSAPublicKey publicKey) {
        this(new SecureRandom(), null, publicKey);
    }

    public RSACrypto(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this(new SecureRandom(), privateKey, publicKey);
    }

    public RSACrypto(SecureRandom random, RSAPrivateKey privateKey) {
        this(random, privateKey, null);
    }

    public RSACrypto(SecureRandom random, RSAPublicKey publicKey) {
        this(random, null, publicKey);
    }

    public RSACrypto(SecureRandom random, RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this.random = random == null ? new SecureRandom() : random;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    @Override
    public Algorithm getAlgorithm() {
        return RSA;
    }

    /* ====================================================================== */

    @Override
    public void close() {
        if ((privateKey == null) && (publicKey == null)) return;
        synchronized (lock) {
            try {
                if (privateKey != null) privateKey.destroy();
            } catch (DestroyFailedException exception) {
                /* Trace, SunJCE private keys are not destroyable */
                log.trace("Unable to destroy private key", exception);
            }
            privateKey = null;
            publicKey = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        synchronized (lock) {
            return ((privateKey == null) && (publicKey == null));
        }
    }

    @Override
    public boolean canEncrypt() {
        synchronized (lock) {
            return publicKey != null;
        }
    }

    @Override
    public boolean canDecrypt() {
        synchronized (lock) {
            return privateKey != null;
        }
    }

    /* ====================================================================== */

    @Override
    public byte[] encrypt(byte[] data)
    throws GeneralSecurityException {
        if (! canEncrypt()) throw new IllegalStateException("Can not encrypt");
        notNull(data, "Null data to encrypt");

        final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        return cipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] data)
    throws GeneralSecurityException {
        if (! canDecrypt()) throw new IllegalStateException("Can not decrypt");
        notNull(data, "No data to decrypt");

        final Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, random);
        return cipher.doFinal(data);
    }

}
