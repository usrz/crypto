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

import static org.usrz.libs.utils.Check.notNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.pem.PEMProvider;
import org.usrz.libs.utils.Check;

public class KeyStoreBuilder {

    private Password password = null;
    private String type = "PEM";
    private File file = null;

    public KeyStoreBuilder() {
        /* Nothing to do */
    }

    public KeyStoreBuilder withConfiguration(Configurations configurations) {
        if (configurations.containsKey("file")) withFile(configurations.getFile("file"));
        if (configurations.containsKey("type")) withType(configurations.get("type"));
        if (configurations.containsKey("password")) withPassword(configurations.getPassword("password"));
        return this;
    }

    public KeyStoreBuilder withFile(File file) {
        this.file = notNull(file, "Null key store file");
        return this;
    }

    public KeyStoreBuilder withPassword(Password password) {
        this.password = Check.<Password>notNull(password, "Null password");
        return this;
    }

    public KeyStoreBuilder withType(String type) {
        this.type = notNull(type, "Null KeyStore type");
        return this;
    }

    public KeyStore build()
    throws GeneralSecurityException, IOException {
        if (file == null) throw new IOException("No file specified for keystore");
        if ("PEM".equalsIgnoreCase(type)) Security.addProvider(new PEMProvider());

        final KeyStore keyStore = KeyStore.getInstance(type);
        final FileInputStream input = new FileInputStream(file);
        keyStore.load(input, password == null ? null : password.get());
        input.close();

        return keyStore;
    }

}
