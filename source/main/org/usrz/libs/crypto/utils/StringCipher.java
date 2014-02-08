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
package org.usrz.libs.crypto.utils;

/**
 * A {@link StringCipher} is used to encode (or decode) {@link String}s.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 * @see StringCipherBuilder
 */
public interface StringCipher {

    /**
     * Encrypt (or decrypt) the specified {@link String}.
     */
    public String transform(String string);

    /**
     * Return the algorithm associated with this {@link StringCipher}.
     *
     * @see StringCipherBuilder#algorithm(String)
     */
    public String getAlgorithm();

    /**
     * Return the initialization vector of with this {@link StringCipher}.
     *
     * @see StringCipherBuilder#initializationVector(byte[])
     */
    public byte[] getInitializationVector();

}
