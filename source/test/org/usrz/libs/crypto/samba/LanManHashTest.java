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
package org.usrz.libs.crypto.samba;

import static org.usrz.libs.utils.codecs.HexCodec.HEX;

import org.testng.annotations.Test;
import org.usrz.libs.crypto.samba.LanManHash;
import org.usrz.libs.testing.AbstractTest;

public class LanManHashTest extends AbstractTest {

    private final LanManHash hash = new LanManHash();

    public void assertPassword(String password, String expected) {
        assertEquals(HEX.encode(hash.hashPassword(password.toCharArray())), expected, "Invalid hash for string \"" + password + "\"");
        assertEquals(HEX.encode(hash.hashPassword(password.toUpperCase().toCharArray())), expected, "Invalid hash for string \"" + password + "\" (upper cased)");
        assertEquals(HEX.encode(hash.hashPassword(password.toLowerCase().toCharArray())), expected, "Invalid hash for string \"" + password + "\" (lower cased)");
    }

    @Test
    public void testLanManPasswordHahes() {
        assertPassword("", "AAD3B435B51404EEAAD3B435B51404EE");
        assertPassword("FooBar", "D85774CF671A9947AAD3B435B51404EE");
        assertPassword("HelloWorld", "AE8E2BDD33EF4DDC8E603EEAE602D4DA");
        assertPassword("HelloWorld1234", "AE8E2BDD33EF4DDC97B9D048FF06F92D");
        assertPassword("HelloWorld123456", "AE8E2BDD33EF4DDC97B9D048FF06F92D"); // same as above, truncate to 14 characters
    }
}

