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
package org.usrz.libs.crypto.pem;

import java.nio.charset.Charset;
import java.security.KeyStore.ProtectionParameter;
import java.util.Arrays;

import org.usrz.libs.crypto.codecs.CharsetCodec;

public final class PEMKeyStorePasswordProtectionParameter implements ProtectionParameter {

    private final byte[] bytes;
    private boolean deleted = false;

    public PEMKeyStorePasswordProtectionParameter(String password) {
        this(password, CharsetCodec.UTF8);
    }

    public PEMKeyStorePasswordProtectionParameter(String password, String charsetName) {
        this(password, Charset.forName(charsetName));
    }

    public PEMKeyStorePasswordProtectionParameter(String password, Charset charset) {
        this(password.getBytes(charset));
    }

    public PEMKeyStorePasswordProtectionParameter(byte[] password) {
        bytes = new byte[password.length];
        System.arraycopy(password, 0, bytes, 0, password.length);
        Arrays.fill(password, (byte) 0);
    }

    public synchronized byte[] getPassword() {
        if (deleted) throw new IllegalStateException("Password already retrieved");
        final byte[] password = new byte[bytes.length];
        System.arraycopy(bytes, 0, password, 0, bytes.length);
        Arrays.fill(password, (byte) 0);
        deleted = true;
        return password;
    }

}
