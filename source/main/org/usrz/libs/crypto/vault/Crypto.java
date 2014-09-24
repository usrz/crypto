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

import java.security.GeneralSecurityException;

import org.usrz.libs.crypto.utils.ClosingDestroyable;

public interface Crypto extends ClosingDestroyable {

    public enum Algorithm { AES, RSA };

    public Algorithm getAlgorithm();

    public boolean canEncrypt();

    public boolean canDecrypt();

    public byte[] decrypt(byte[] data)
    throws GeneralSecurityException;

    public byte[] encrypt(byte[] data)
    throws GeneralSecurityException;

}
