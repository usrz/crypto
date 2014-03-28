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

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.utils.configurations.Configurations;
import org.usrz.libs.utils.configurations.ResourceConfigurations;

public class SecureConfigurationsTest extends AbstractTest {

    @Test
    public void testSecureConfigurations()
    throws Exception {
        final Configurations configurations = new ResourceConfigurations("secure.properties");
        final VaultBuilder builder = new VaultBuilder(new ResourceConfigurations("vault.json"));
        final Vault vault = builder.withPassword("foobar").build();
        final SecureConfigurations secure = new SecureConfigurations(configurations, vault);

        assertEquals(secure.requireString("foo.string"), "this is a string");
        assertEquals(secure.requireInteger("foo.number"), 12345);
        assertEquals(secure.requireBoolean("foo.boolean"), true);

    }

}
