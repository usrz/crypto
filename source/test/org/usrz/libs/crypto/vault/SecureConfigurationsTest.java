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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.testng.annotations.Test;
import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.ConfigurationsBuilder;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.configurations.ResourceConfigurations;
import org.usrz.libs.testing.AbstractTest;

public class SecureConfigurationsTest extends AbstractTest {

    @Test(expectedExceptions=IllegalStateException.class,
          expectedExceptionsMessageRegExp="Some keys are both available in encrypted and decrypted format: \\[foo\\]")
    public void testSecureConfigurationsDuplicate()
    throws Exception {
        final Password password = new Password("foobar".toCharArray());
        new SecureConfigurations(new ConfigurationsBuilder()
                                         .put("foo", "foo")
                                         .put("foo.$encrypted", "bar")
                                         .build(),
                                 new VaultBuilder(new ResourceConfigurations("vault.json"))
                                         .withPassword(password)
                                         .build())
                .close();
        password.close();
    }

    @Test
    public void testSecureConfigurations1()
    throws Exception {
        final Configurations configurations = new ResourceConfigurations("secure.properties");
        final VaultBuilder builder = new VaultBuilder(new ResourceConfigurations("vault.json"));

        final Password password = new Password("foobar".toCharArray());
        final Vault vault = builder.withPassword(password).build();
        password.close();

        final SecureConfigurations secure = new SecureConfigurations(configurations, vault, true);

        assertEquals(secure.requireString("foo.unencrypted"), "this is not encrypted");
        assertEquals(secure.requireString("foo.string"), "this is a string");
        assertEquals(secure.requireInteger("foo.number"), 12345);
        assertEquals(secure.requireBoolean("foo.boolean"), true);

        final Set<String> keys = new HashSet<>(Arrays.asList("foo.unencrypted",
                                                             "foo.string.$encrypted",
                                                             "foo.number.$encrypted",
                                                             "foo.boolean.$encrypted"));
        assertEquals(secure.keySet(), keys, "Invalid set keys returned from configuration");

        vault.close();
        secure.close();
    }

    @Test
    public void testSecureConfigurations2()
    throws Exception {
        final Configurations configurations = new ResourceConfigurations("secure.json");
        final Password password = new Password("foobar".toCharArray());
        final SecureConfigurations secure = new SecureConfigurations(configurations, password, true);
        password.close();

        assertEquals(secure.requireString("foo.unencrypted"), "this is not encrypted");
        assertEquals(secure.requireString("foo.string"), "this is a string");
        assertEquals(secure.requireInteger("foo.number"), 12345);
        assertEquals(secure.requireBoolean("foo.boolean"), true);

        final Set<String> keys = new HashSet<>(Arrays.asList("foo.unencrypted",
                                                             "foo.string.$encrypted",
                                                             "foo.number.$encrypted",
                                                             "foo.boolean.$encrypted"));
        assertEquals(secure.keySet(), keys, "Invalid set keys returned from configuration");
        secure.close();
    }

    @Test
    public void testSecureConfigurationsNonLenient()
    throws Exception {
        final Configurations configurations = new ResourceConfigurations("secure.json");
        final Password password = new Password("foobar".toCharArray());
        final SecureConfigurations secure = new SecureConfigurations(configurations, password, false);
        password.close();

        assertEquals(secure.requireString("foo.unencrypted"), "this is not encrypted");
        assertEquals(secure.requirePassword("foo.string").get(), "this is a string".toCharArray());
        assertEquals(secure.requirePassword("foo.number").get(), "12345".toCharArray());
        assertEquals(secure.requirePassword("foo.boolean").get(), "true".toCharArray());

        final Set<String> keys = new HashSet<>(Arrays.asList("foo.unencrypted",
                                                             "foo.string.$encrypted",
                                                             "foo.number.$encrypted",
                                                             "foo.boolean.$encrypted"));
        assertEquals(secure.keySet(), keys, "Invalid set keys returned from configuration");

        try {
            secure.requireString("foo.string");
            fail("The requireString method should throw an IllegalStateException");
        } catch (IllegalStateException exception) {
            assertEquals(exception.getMessage(), "Unable to retrieve encrypted value for \"foo.string\" (not lenient)", "Exception message");
        }

        try {
            secure.close();
            assertTrue(password.isDestroyed(), "Configurations not destroyed");
            secure.requirePassword("foo.string");
        } catch (IllegalStateException exception) {
            assertEquals(exception.getMessage(), "Vault destroyed");
        }
    }

    @Test
    public void testDestroy()
    throws Exception {
        final Configurations configurations = new ResourceConfigurations("secure.properties");
        final VaultBuilder builder = new VaultBuilder(new ResourceConfigurations("vault.json"));
        final Password password = new Password("foobar".toCharArray());

        @SuppressWarnings("resource")
        final Vault vault = builder.withPassword(password).build();
        password.close();

        final SecureConfigurations secure = new SecureConfigurations(configurations, vault, true);

        assertEquals(secure.requireString("foo.unencrypted"), "this is not encrypted");
        assertEquals(secure.requireString("foo.string"), "this is a string");

        secure.close();
        assertTrue(secure.isDestroyed(), "Not destroyed?");
        assertTrue(vault.isDestroyed(), "Vault Not destroyed?");
        assertEquals(secure.requireString("foo.unencrypted"), "this is not encrypted");
        try {
            secure.getString("foo.string");
            fail("IllegalStateException never thrown");
        } catch (IllegalStateException exception) {
            assertEquals(exception.getMessage(), "Vault destroyed");
        }
    }

}
