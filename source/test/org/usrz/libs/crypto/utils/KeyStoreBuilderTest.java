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

import java.security.KeyStore;

import org.testng.annotations.Test;
import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.ConfigurationsBuilder;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.vault.SecureConfigurations;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.testing.IO;

public class KeyStoreBuilderTest extends AbstractTest {

    @Test
    public void testKeyStoreBuilderPEMEncrypted() throws Exception {
        @SuppressWarnings("resource")
        final Configurations configurations = new SecureConfigurations(new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("encrypted.pem"))
                .put("password", "asdf")
                .put("type", "pem")
                .build());
        final KeyStore keyStore = new KeyStoreBuilder()
                .withConfiguration(configurations)
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
                .withConfiguration(configurations)
                .build();

        assertNotNull(keyStore.getKey("B4C67B3BA4FA10F0B219B079E73E986D671E8385", null));
        assertNotNull(keyStore.getCertificate("B4C67B3BA4FA10F0B219B079E73E986D671E8385"));
    }

    @Test
    public void testKeyStoreBuilderPEMPassword() throws Exception {
        final Configurations configurations = new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("encrypted.pem"))
                .put("type", "pem")
                .build();

        final Password password = new Password("asdf".toCharArray());
        final KeyStore keyStore = new KeyStoreBuilder()
                .withConfiguration(configurations)
                .withPassword(password)
                .build();
        password.close();

        assertNotNull(keyStore.getKey("F7A4FD46266A272B145B4F09F6D14CC7A458268B", "asdf".toCharArray()));
        assertNotNull(keyStore.getCertificate("F7A4FD46266A272B145B4F09F6D14CC7A458268B"));
    }

    /* ====================================================================== */

    @Test
    public void testKeyStoreBuilderJKS() throws Exception {
        @SuppressWarnings("resource")
        final Configurations configurations = new SecureConfigurations(new ConfigurationsBuilder()
                .put("file", IO.copyTempFile("keystore.jks"))
                .put("password", "asdfgh")
                .put("type", "jks")
                .build());
        final KeyStore keyStore = new KeyStoreBuilder()
                .withConfiguration(configurations)
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

        final Password password = new Password("asdfgh".toCharArray());
        final KeyStore keyStore = new KeyStoreBuilder()
                .withConfiguration(configurations)
                .withPassword(password)
                .build();
        password.close();

        assertNotNull(keyStore.getKey("myAlias", "qwerty".toCharArray()));
        assertNotNull(keyStore.getCertificate("myAlias"));
    }

}
