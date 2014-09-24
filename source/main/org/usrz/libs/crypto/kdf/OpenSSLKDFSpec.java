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

import static org.usrz.libs.crypto.kdf.KDF.Function.OPENSSL;

import org.usrz.libs.crypto.hash.Hash;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * A {@link KDFSpec} for the {@link OpenSSLKDF} KDF.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
@JsonPropertyOrder({"function","hash","derivedKeyLength"})
public class OpenSSLKDFSpec extends AbstractKDFSpec {

    public OpenSSLKDFSpec() {
        this(null, 0);
    }

    public OpenSSLKDFSpec(Hash hash, int derivedKeyLength) {
        super(OPENSSL, hash, derivedKeyLength);
    }

    /* No extra properties for OpenSSL */

}
