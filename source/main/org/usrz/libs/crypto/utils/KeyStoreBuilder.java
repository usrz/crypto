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

import static org.usrz.libs.utils.Check.check;
import static org.usrz.libs.utils.Check.notNull;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.util.Arrays;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.crypto.pem.PEMProvider;

public class KeyStoreBuilder {

    private CallbackHandler handler = null;
    private char[] password = null;
    private String type = "PEM";
    private File file = null;

    public KeyStoreBuilder() {
        /* Nothing to do */
    }

    public KeyStoreBuilder configuration(Configurations configurations) {
        if (configurations.containsKey("file")) this.file(configurations.getFile("file"));
        if (configurations.containsKey("type")) type(configurations.get("type"));
        if (configurations.containsKey("password")) this.password(configurations.get("password").toCharArray());
        return this;
    }

    public KeyStoreBuilder file(File file) {
        this.file = notNull(file, "Null key store file");
        return this;
    }

    public KeyStoreBuilder password(CallbackHandler handler) {
        if (this.handler != null) throw new IllegalStateException("Callback handler already specified");
        if (password != null) throw new IllegalStateException("Password already specified");
        this.handler = notNull(handler, "Null callback handler");
        return this;
    }

    public KeyStoreBuilder password(char[] password) {
        if (handler != null) throw new IllegalStateException("Callback handler already specified");
        if (this.password != null) throw new IllegalStateException("Password already specified");

        notNull(password, "Null key store password");
        check(password, password.length > 0, "Empty password");

        this.password = new char[password.length];
        System.arraycopy(password, 0, this.password, 0, password.length);
        Arrays.fill(password, '\0');

        return this;
    }

    public KeyStoreBuilder type(String type) {
        this.type = notNull(type, "Null KeyStore type");
        return this;
    }

    public KeyStore build()
    throws GeneralSecurityException, IOException {
        if (file == null) throw new IOException("No file specified for keystore");
        if ("PEM".equalsIgnoreCase(type)) Security.addProvider(new PEMProvider());

        if (handler != null) try {
            final PasswordCallback callback = new PasswordCallback("Enter password for key store " + file, false);
            handler.handle(new Callback[] { callback });
            final char[] password = callback.getPassword();
            if (password != null) {
                this.password = new char[password.length];
                System.arraycopy(password, 0, this.password, 0, password.length);
                callback.clearPassword();
            }
        } catch (UnsupportedCallbackException exception) {
            throw new GeneralSecurityException("Callback unsupported", exception);
        }

        final KeyStore keyStore = KeyStore.getInstance(type);
        keyStore.load(new FileInputStream(file), password);
        if (password != null) Arrays.fill(password, '\0');
        return keyStore;
    }

}
