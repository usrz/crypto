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

import static org.usrz.libs.crypto.vault.CryptoSpecBuilder.ALGORITHM;
import static org.usrz.libs.crypto.vault.VaultSpecBuilder.CODEC_SPEC;
import static org.usrz.libs.utils.Check.notNull;
import static org.usrz.libs.utils.codecs.CodecManager.getCodec;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ALGORITHM, CODEC_SPEC})
public class RSAVaultSpec extends RSACryptoSpec implements VaultSpec {

    private final String codecSpec;

    public RSAVaultSpec(String codecSpec) {
        this.codecSpec = getCodec(notNull(codecSpec, "Null codec spec")).getCodecSpec();
    }

    @Override
    @JsonProperty(CODEC_SPEC)
    public String getCodecSpec() {
        return codecSpec;
    }

    /* ====================================================================== */

    @Override
    public boolean equals(Object object) {
        if (object == null) return false;
        if (object == this) return true;
        try {
            final RSAVaultSpec spec = (RSAVaultSpec) object;
            return super.equals(spec) && getCodecSpec().equals(spec.getCodecSpec());
        } catch (ClassCastException exception) {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return (super.hashCode() * 31) ^ getCodecSpec().hashCode();
    }

}
