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
import org.usrz.libs.configurations.ResourceConfigurations;
import org.usrz.libs.testing.AbstractTest;

public class SecureConfigurationsTest extends AbstractTest {

    @Test
    public void testSecureConfigurations1()
    throws Exception {
        final Configurations configurations = new ResourceConfigurations("secure.properties");
        final VaultBuilder builder = new VaultBuilder(new ResourceConfigurations("vault.json"));
        final Vault vault = builder.withPassword("foobar".toCharArray()).build();
        final SecureConfigurations secure = new SecureConfigurations(configurations, vault);

        assertEquals(secure.requireString("foo.unencrypted"), "this is not encrypted");
        assertEquals(secure.requireString("foo.string"), "this is a string");
        assertEquals(secure.requireInteger("foo.number"), 12345);
        assertEquals(secure.requireBoolean("foo.boolean"), true);

        final Set<String> keys = new HashSet<>(Arrays.asList("foo.unencrypted",
                                                             "foo.string",
                                                             "foo.number",
                                                             "foo.boolean"));
        assertEquals(secure.keySet(), keys, "Invalid set keys returned from configuration");
    }

    @Test
    public void testSecureConfigurations2()
    throws Exception {
        final Configurations configurations = new ResourceConfigurations("secure.json");
        final SecureConfigurations secure = new SecureConfigurations(configurations, "foobar".toCharArray());

        assertEquals(secure.requireString("foo.unencrypted"), "this is not encrypted");
        assertEquals(secure.requireString("foo.string"), "this is a string");
        assertEquals(secure.requireInteger("foo.number"), 12345);
        assertEquals(secure.requireBoolean("foo.boolean"), true);

        final Set<String> keys = new HashSet<>(Arrays.asList("foo.unencrypted",
                                                             "foo.string",
                                                             "foo.number",
                                                             "foo.boolean"));
        assertEquals(secure.keySet(), keys, "Invalid set keys returned from configuration");
    }
}
