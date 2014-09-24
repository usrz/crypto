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

import static org.usrz.libs.crypto.vault.VaultSpecBuilder.CODEC_SPEC;

import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.utils.codecs.Codec;
import org.usrz.libs.utils.codecs.CodecManager;

public class VaultBuilder extends CryptoBuilder {

    private String codecSpec = "HEX";

    public VaultBuilder(Configurations configurations) {
        super(configurations);
        codecSpec = configurations.get(CODEC_SPEC, codecSpec);
    }

    public VaultBuilder(VaultSpec spec) {
        super(spec);
        codecSpec = spec.getCodecSpec();
    }

    @Override
    public Vault build() {
        final Codec codec = CodecManager.getCodec(codecSpec);
        return new Vault(super.build(), codec);
    }

    @Override
    public VaultBuilder withRandom(SecureRandom random) {
        super.withRandom(random);
        return this;
    }

    @Override
    public VaultBuilder withPrivateKey(RSAPrivateKey privateKey) {
        super.withPrivateKey(privateKey);
        return this;
    }

    @Override
    public VaultBuilder withPublicKey(RSAPublicKey publicKey) {
        super.withPublicKey(publicKey);
        return this;
    }

    @Override
    public VaultBuilder withPassword(Password password) {
        super.withPassword(password);
        return this;
    }

}
