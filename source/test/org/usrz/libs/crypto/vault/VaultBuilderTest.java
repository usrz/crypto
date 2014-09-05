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
import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.ResourceConfigurations;
import org.usrz.libs.testing.AbstractTest;

public class VaultBuilderTest extends AbstractTest {

    @Test
    public void testVaultBuilder() throws Exception {
        final Configurations configurations = new ResourceConfigurations("vault.json");
        final VaultBuilder builder = new VaultBuilder(configurations);
        final Vault vault = builder.withPassword("foobar".toCharArray()).build();

        /* Symmetric encryption/decryption */
        final String encrypted = vault.encrypt("hello, world!");
        final String decrypted = vault.decryptString(encrypted);
        assertEquals(decrypted, "hello, world!");

        /* Well known value with password "foobar" */
        assertEquals(vault.decryptString("ZFGDwOaXLILommCHFbB4-cOR0toqVTaibspiy65aqkBZZ2tN40wK4t70V2iIqGcx"), "this is a well-known value");
    }

}
