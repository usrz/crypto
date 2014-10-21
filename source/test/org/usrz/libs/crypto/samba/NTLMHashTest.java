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
import org.usrz.libs.crypto.samba.NTLMHash;
import org.usrz.libs.testing.AbstractTest;

public class NTLMHashTest extends AbstractTest {

    private final NTLMHash hash = new NTLMHash();

    private final void assertPassword(String password, String expected) {
        final byte[] result = hash.hashPassword(password.toCharArray());
        assertEquals(HEX.encode(result), expected, "Invalid hash for string \"" + password + "\"");
        if (! password.toLowerCase().equals(password)) {
            assertNotEquals(hash.hashPassword(password.toLowerCase().toCharArray()), result, "Lower case hash for \"" + password + "\" matches");
        }
        if (! password.toUpperCase().equals(password)) {
            assertNotEquals(hash.hashPassword(password.toUpperCase().toCharArray()), result, "Lower case hash for \"" + password + "\" matches");
        }
    }

    @Test
    public void testNTLMPasswordHahes() {
        assertPassword("", "31D6CFE0D16AE931B73C59D7E0C089C0");

        assertPassword("FooBar", "F5279312D3F4724BDA4A8552A0B53E10");
        assertPassword("HelloWorld", "F37F57A03351C09D237508F14BAB2AE3");
        assertPassword("HelloWorld1234", "F301C70110D7295C109DFF40A40FA12E");
        assertPassword("HelloWorld123456", "67FCB2387BC2F5E897EABB3965B8E23D");

        /* Different, lower cased... */
        assertPassword("foobar", "BAAC3929FABC9E6DCD32421BA94A84D4");
        assertPassword("helloworld", "72FC5EF38C07F24388017C748CEAB330");
        assertPassword("helloworld1234", "C9AD8E0EA52E86414788608A1307DC00");
        assertPassword("helloworld123456", "6B573AFB0B8611BB4937C46E26954B67");

        /* Different, upper cased... */
        assertPassword("FOOBAR", "BE92D7132A225F85B5566E2D000D8B21");
        assertPassword("HELLOWORLD", "6CA336C820344149D594131B2DF55077");
        assertPassword("HELLOWORLD1234", "530110AC412CC10B84551C09AF611559");
        assertPassword("HELLOWORLD123456", "5BD4CF778A5BBF0E1BF82C97DDB41307");
    }
}
