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

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.crypto.kdf.KDFSpec;
import org.usrz.libs.crypto.kdf.KDFSpecBuilder;
import org.usrz.libs.crypto.vault.Crypto.Algorithm;
import org.usrz.libs.utils.Check;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonPOJOBuilder;

@JsonPOJOBuilder
public class CryptoSpecBuilder {

    public static final String KDF_SPEC = "kdf";
    public static final String ALGORITHM = "algorithm";

    private final Algorithm algorithm;
    private KDFSpec kdfSpec;

    @JsonCreator
    public CryptoSpecBuilder(@JsonProperty(ALGORITHM) String algorithm) {
        Check.notNull(algorithm, "Null algorithm");
        try {
            this.algorithm = Algorithm.valueOf(algorithm.toUpperCase());
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Invalid algorithm \"" + algorithm + "\"", exception);
        }
    }

    public CryptoSpecBuilder(Algorithm algorithm) {
        this.algorithm = Check.notNull(algorithm, "Null algorithm");
    }

    public CryptoSpecBuilder(Configurations configurations) {
        Check.notNull(configurations, "Null configurations");
        final String algorithm = configurations.requireString(ALGORITHM);
        try {
            this.algorithm = Algorithm.valueOf(algorithm.toUpperCase());
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("Invalid algorithm \"" + algorithm + "\"", exception);
        }
        withConfigurations(configurations);
    }

    /* ====================================================================== */

    public CryptoSpec build() {
        switch (algorithm) {
            case AES:
                if (kdfSpec == null) throw new IllegalStateException("KDF spec missing for AES");
                return new AESCryptoSpec(kdfSpec);
            case RSA:
                return new RSACryptoSpec();
            default:
                throw new IllegalStateException("Unsupported algorithm " + algorithm);
        }
    }

    /* ====================================================================== */

    @JsonProperty(KDF_SPEC)
    public CryptoSpecBuilder withKDFSpec(KDFSpec kdfSpec) {
        this.kdfSpec = Check.notNull(kdfSpec, "Null KDF spec");
        return this;
    }

    @JsonIgnore
    public CryptoSpecBuilder withConfigurations(Configurations configurations) {
        final Configurations kdfConfigs = configurations.strip(KDF_SPEC);
        if (!kdfConfigs.isEmpty()) kdfSpec = new KDFSpecBuilder(kdfConfigs).build();
        return this;
    }

}
