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

import static org.usrz.libs.utils.Charsets.UTF8;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.usrz.libs.crypto.kdf.KDF;
import org.usrz.libs.utils.codecs.Codec;

public class AESVault implements Vault {

    private final KDF kdf;
    private final Codec codec;
    private final SecureRandom random;
    private final byte[] password;

    public AESVault(Codec codec, KDF kdf, String password) {
        this(new SecureRandom(), codec, kdf, password);
    }

    public AESVault(SecureRandom random, Codec codec, KDF kdf, String password) {
        this.kdf = kdf;
        this.codec = codec;
        this.random = random;
        this.password = password.getBytes(UTF8);
    }

    @Override
    public boolean canEncrypt() {
        return true;
    }

    @Override
    public boolean canDecrypt() {
        return true;
    }

    @Override
    public String encrypt(String string)
    throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        final byte[] salt = new byte[cipher.getBlockSize()];
        random.nextBytes(salt);

        final byte[] key = kdf.deriveKey(password, salt);

        final IvParameterSpec ivParameterSpec = new IvParameterSpec(salt);
        final SecretKey secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        final byte[] encrypted = cipher.doFinal(string.getBytes(UTF8));

        final byte[] result = new byte[salt.length + encrypted.length];
        System.arraycopy(salt, 0, result, 0, salt.length);
        System.arraycopy(encrypted, 0, result, salt.length, encrypted.length);

        return codec.encode(result);
    }

    @Override
    public String decrypt(String string)
    throws GeneralSecurityException {
        final byte[] decoded = codec.decode(string);

        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        final byte[] salt = new byte[cipher.getBlockSize()];
        System.arraycopy(decoded, 0, salt, 0, salt.length);

        final byte[] key = kdf.deriveKey(password, salt);

        final IvParameterSpec ivParameterSpec = new IvParameterSpec(salt);
        final SecretKey secretKey = new SecretKeySpec(key, "AES");

        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        final byte[] decrypted = cipher.doFinal(decoded, salt.length, decoded.length - salt.length);

        return new String(decrypted, UTF8);
    }

}
