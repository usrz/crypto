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

import java.io.IOException;
import java.security.KeyStore;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.testng.annotations.Test;
import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.ConfigurationsBuilder;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.testing.IO;

public class KeyStoreBuilderTest extends AbstractTest {

    @Test
    public void testKeyStoreBuilderPEMEncrypted() throws Exception {
        final Configurations configurations = new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("encrypted.pem"))
                .put("password", "asdf")
                .put("type", "pem")
                .build();
        final KeyStore keyStore = new KeyStoreBuilder()
                .configuration(configurations)
                .build();

        assertNotNull(keyStore.getKey("F7A4FD46266A272B145B4F09F6D14CC7A458268B", "asdf".toCharArray()));
        assertNotNull(keyStore.getCertificate("F7A4FD46266A272B145B4F09F6D14CC7A458268B"));
    }

    @Test
    public void testKeyStoreBuilderPEMUnencrypted() throws Exception {
        final Configurations configurations = new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("unencrypted.pem"))
                .put("type", "pem")
                .build();
        final KeyStore keyStore = new KeyStoreBuilder()
                .configuration(configurations)
                .build();

        assertNotNull(keyStore.getKey("B4C67B3BA4FA10F0B219B079E73E986D671E8385", null));
        assertNotNull(keyStore.getCertificate("B4C67B3BA4FA10F0B219B079E73E986D671E8385"));
    }

    @Test
    public void testKeyStoreBuilderPEMCallback() throws Exception {
        final Configurations configurations = new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("encrypted.pem"))
                .put("type", "pem")
                .build();

        final KeyStore keyStore = new KeyStoreBuilder()
                .configuration(configurations)
                .password(new CallbackHandler() {

                    @Override
                    public void handle(Callback[] callbacks)
                    throws IOException, UnsupportedCallbackException {
                        try {
                            ((PasswordCallback) callbacks[0]).setPassword("asdf".toCharArray());
                        } catch (ClassCastException exception) {
                            throw new UnsupportedCallbackException(callbacks[0], "FOO!");
                        }
                    }

                })
                .build();

        assertNotNull(keyStore.getKey("F7A4FD46266A272B145B4F09F6D14CC7A458268B", "asdf".toCharArray()));
        assertNotNull(keyStore.getCertificate("F7A4FD46266A272B145B4F09F6D14CC7A458268B"));
    }

    /* ====================================================================== */

    @Test
    public void testKeyStoreBuilderJKS() throws Exception {
        final Configurations configurations = new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("keystore.jks"))
                .put("password", "asdfgh")
                .put("type", "jks")
                .build();
        final KeyStore keyStore = new KeyStoreBuilder()
                .configuration(configurations)
                .build();

        assertNotNull(keyStore.getKey("myAlias", "qwerty".toCharArray()));
        assertNotNull(keyStore.getCertificate("myAlias"));
    }

    @Test
    public void testKeyStoreBuilderJKSCallback() throws Exception {

        final Configurations configurations = new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("keystore.jks"))
                .put("type", "jks")
                .build();

        final KeyStore keyStore = new KeyStoreBuilder()
                .configuration(configurations)
                .password(new CallbackHandler() {

                    @Override
                    public void handle(Callback[] callbacks)
                    throws IOException, UnsupportedCallbackException {
                        try {
                            ((PasswordCallback) callbacks[0]).setPassword("asdfgh".toCharArray());
                        } catch (ClassCastException exception) {
                            throw new UnsupportedCallbackException(callbacks[0], "FOO!");
                        }
                    }

                })
                .build();

        assertNotNull(keyStore.getKey("myAlias", "qwerty".toCharArray()));
        assertNotNull(keyStore.getCertificate("myAlias"));
    }

}
