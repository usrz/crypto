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
package org.usrz.libs.crypto.kdf;

import static org.usrz.libs.crypto.codecs.CharsetCodec.UTF8;
import static org.usrz.libs.crypto.codecs.HexCodec.HEX;

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;

public class OpenSSLKDFTest extends AbstractTest {

    final byte[] pass = "password".getBytes(UTF8);
    final byte[] salt = HEX.decode("E626005A8C9FE8EC");

    @Test
    public void testShort() {
        final OpenSSLKDF kdf = new OpenSSLKDF(8);
        final byte[] result = kdf.deriveKey(pass, salt);
        assertEquals(result, HEX.decode("ba87b69741a4d7da"));
    }

    @Test
    public void testSimple() {
        final OpenSSLKDF kdf = new OpenSSLKDF(16);
        final byte[] result = kdf.deriveKey(pass, salt);
        assertEquals(result, HEX.decode("ba87b69741a4d7dab15e972c07e7d9f1"));
    }

    @Test
    public void testLong() {
        final OpenSSLKDF kdf = new OpenSSLKDF(24);
        final byte[] result = kdf.deriveKey(pass, salt);
        assertEquals(result, HEX.decode("ba87b69741a4d7dab15e972c07e7d9f18b43599a81d1bbef"));
    }

    @Test
    public void testAlternative() {
        final OpenSSLKDF kdf = new OpenSSLKDF(16);
        final byte[] result = kdf.deriveKey("asdf".getBytes(UTF8), HEX.decode("9018B9965CB475A3"));
        assertEquals(result, HEX.decode("ED1F1DE2ECD77EA1DC5F08465EF36402"));
    }

}
