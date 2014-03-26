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
package org.usrz.libs.crypto.json;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "typ", "alg"})
public class JsonWebTokenHeader {

    private final String type;
    private final String algorithm;

    @JsonCreator
    public JsonWebTokenHeader(@JsonProperty("typ") String type,
                              @JsonProperty("alg") String algorithm) {
        this.type = Objects.requireNonNull(type, "Null type");
        this.algorithm = Objects.requireNonNull(algorithm, "Null algorithm");
    }

    @JsonProperty("typ")
    public String getType() {
        return type;
    }

    @JsonProperty("alg")
    public String getAlgorithm() {
        return algorithm;
    }

}