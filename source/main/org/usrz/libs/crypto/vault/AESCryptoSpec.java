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

import static org.usrz.libs.crypto.vault.Crypto.Algorithm.AES;
import static org.usrz.libs.crypto.vault.CryptoSpecBuilder.ALGORITHM;
import static org.usrz.libs.crypto.vault.CryptoSpecBuilder.KDF_SPEC;

import org.usrz.libs.crypto.kdf.KDFSpec;
import org.usrz.libs.crypto.vault.Crypto.Algorithm;
import org.usrz.libs.utils.Check;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ALGORITHM, KDF_SPEC})
public class AESCryptoSpec implements CryptoSpec {

    private final KDFSpec kdfSpec;

    public AESCryptoSpec(KDFSpec kdfSpec) {
        this.kdfSpec = Check.notNull(kdfSpec, "Null KDF spec");
    }

    @Override
    public Algorithm getAlgorithm() {
        return AES;
    }

    @JsonProperty(KDF_SPEC)
    public KDFSpec getKDFSpec() {
        return kdfSpec;
    }
}
