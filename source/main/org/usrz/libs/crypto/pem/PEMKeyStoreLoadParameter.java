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

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.KeyStore;

public final class PEMKeyStoreLoadParameter implements KeyStore.LoadStoreParameter {

    private final File storeDirectory;
    private final PEMKeyStorePasswordProtectionParameter protectionParameter;

    public PEMKeyStoreLoadParameter(final File storeDirectory) {
        this.storeDirectory = validateStoreDirectory(storeDirectory);
        protectionParameter = null;
    }

    public PEMKeyStoreLoadParameter(final File storeDirectory, String defaultPassword) {
        this.storeDirectory = validateStoreDirectory(storeDirectory);
        protectionParameter = new PEMKeyStorePasswordProtectionParameter(defaultPassword);
    }

    public PEMKeyStoreLoadParameter(final File storeDirectory, String defaultPassword, String passwordCharsetName) {
        this.storeDirectory = validateStoreDirectory(storeDirectory);
        protectionParameter = new PEMKeyStorePasswordProtectionParameter(defaultPassword);
    }

    public PEMKeyStoreLoadParameter(final File storeDirectory, String defaultPassword, Charset passwordCharset) {
        this.storeDirectory = validateStoreDirectory(storeDirectory);
        protectionParameter = new PEMKeyStorePasswordProtectionParameter(defaultPassword);
    }

    public PEMKeyStoreLoadParameter(final File storeDirectory, byte[] defaultPassword) {
        this.storeDirectory = validateStoreDirectory(storeDirectory);
        protectionParameter = new PEMKeyStorePasswordProtectionParameter(defaultPassword);
    }

    /* ====================================================================== */

    private static File validateStoreDirectory(File storeDirectory) {
        if (storeDirectory == null) throw new NullPointerException("Null store directory");
        if (!storeDirectory.isDirectory()) throw new IllegalArgumentException("Store directory \"" + storeDirectory.getAbsolutePath() + "\" is not a directory");
        try {
            return storeDirectory.getCanonicalFile();
        } catch (IOException exception) {
            throw new IllegalArgumentException("Unable to resolve store directory \"" + storeDirectory.getAbsolutePath() + "\"", exception);
        }
    }

    /* ====================================================================== */

    public File getStoreDirectory() {
        return storeDirectory;
    }

    @Override
    public PEMKeyStorePasswordProtectionParameter getProtectionParameter() {
        return protectionParameter;
    }

}
