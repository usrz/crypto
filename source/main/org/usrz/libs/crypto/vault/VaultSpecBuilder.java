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

import static org.usrz.libs.utils.Check.notNull;
import static org.usrz.libs.utils.codecs.CodecManager.getCodec;
import static org.usrz.libs.utils.codecs.HexCodec.HEX;

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.crypto.kdf.KDFSpec;
import org.usrz.libs.crypto.vault.Crypto.Algorithm;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@JsonPOJOBuilder
public class VaultSpecBuilder extends CryptoSpecBuilder {

    public static final String CODEC_SPEC = "codec";

    private String codecSpec = HEX.getCodecSpec(); // default

    @JsonCreator
    public VaultSpecBuilder(@JsonProperty(ALGORITHM) String algorithm) {
        super(algorithm);
    }

    public VaultSpecBuilder(Algorithm algorithm) {
        super(algorithm);
    }

    public VaultSpecBuilder(Configurations configurations) {
        super(configurations);
    }

    /* ====================================================================== */

    @Override
    public VaultSpec build() {
        final CryptoSpec spec = super.build();
        switch (spec.getAlgorithm()) {
            case AES: return new AESVaultSpec(((AESCryptoSpec) spec).getKDFSpec(), codecSpec);
            case RSA: return new RSAVaultSpec(codecSpec);
            default: throw new IllegalStateException("Unsupported algorithm " + spec.getAlgorithm());
        }
    }

    /* ====================================================================== */

    @Override
    @JsonProperty(KDF_SPEC)
    public VaultSpecBuilder withKDFSpec(KDFSpec kdfSpec) {
        super.withKDFSpec(kdfSpec);
        return this;
    }

    @Override
    @JsonIgnore
    public VaultSpecBuilder withConfigurations(Configurations configurations) {
        super.withConfigurations(configurations);
        withCodecSpec(configurations.get(CODEC_SPEC, codecSpec));
        return this;
    }

    @JsonProperty(CODEC_SPEC)
    public VaultSpecBuilder withCodecSpec(String codecSpec) {
        this.codecSpec = getCodec(notNull(codecSpec, "Null codec spec")).getCodecSpec();
        return this;
    }
}
