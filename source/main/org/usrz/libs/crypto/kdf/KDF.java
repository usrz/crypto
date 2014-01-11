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

/**
 * The {@link KDF} interface defines a component capable of derivating a
 * key from a password and <i>salt</i>.
 *
 * @see <a href="http://en.wikipedia.org/wiki/Key_derivation_function">Key
 *      derivation functions</a>
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public interface KDF {

    /**
     * Return the length (in bytes) of the derived key.
     */
    public int getDerivedKeyLength();

    /**
     * Derive a key from the specified password and <i>salt</i>, and return it
     * into a new <code>byte[]</code>.
     *
     * @throws NullPointerException If password or <i>salt</i> were <b>null</b>.
     */
    public byte[] deriveKey(byte[] password, byte[] salt)
    throws NullPointerException;

    /**
     * Derive a key from the specified password and <i>salt</i> and write in the
     * specified <code>byte[]</code> at the specified position.
     *
     * @throws NullPointerException If password, <i>salt</i> or output buffer
     *                              were <b>null</b>.
     * @throws IllegalArgumentException If the buffer was not big enough.
     */
    public void deriveKey(byte[] password, byte[] salt, byte[] output, int offset)
    throws NullPointerException, IllegalArgumentException;

}
