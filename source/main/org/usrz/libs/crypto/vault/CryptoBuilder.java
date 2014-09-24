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

import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.kdf.BasicKDFManager;
import org.usrz.libs.crypto.kdf.KDF;
import org.usrz.libs.utils.Check;

public class CryptoBuilder {

    private final CryptoSpec spec;

    private SecureRandom random;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private Password password;

    public CryptoBuilder(Configurations configurations) {
        this(new CryptoSpecBuilder(Check.notNull(configurations, "Null configurations")).build());
    }

    public CryptoBuilder(CryptoSpec spec) {
        this.spec = Check.notNull(spec, "Null crypto spec");
    }

    public Crypto build() {
        switch (spec.getAlgorithm()) {
            case AES:
                final AESCryptoSpec aesSpec = (AESCryptoSpec) spec;
                final KDF kdf = new BasicKDFManager().getKDF(aesSpec.getKDFSpec());
                if (password == null) throw new IllegalStateException("Missing password");
                return new AESCrypto(random, kdf, password);

            case RSA:
                if ((privateKey == null) && (publicKey == null))
                    throw new IllegalStateException("Either private and/or public key must be specified");
                return new RSACrypto(random, privateKey, publicKey);

            default:
                throw new IllegalStateException("Unsupported algorithm " + spec.getAlgorithm());
        }
    }

    public CryptoBuilder withRandom(SecureRandom random) {
        this.random = Check.notNull(random, "Null random");
        return this;
    }

    public CryptoBuilder withPrivateKey(RSAPrivateKey privateKey) {
        this.privateKey = Check.notNull(privateKey, "Null private key");
        return this;
    }

    public CryptoBuilder withPublicKey(RSAPublicKey publicKey) {
        this.publicKey = Check.notNull(publicKey, "Null public key");
        return this;
    }

    public CryptoBuilder withPassword(Password password) {
        this.password = Check.<Password>notNull(password, "Null password");
        return this;
    }

}
