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
package org.usrz.libs.crypto.pem;

import static org.usrz.libs.utils.Charsets.ASCII;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.testing.IO;

public class PEMCombiningInputStreamTest extends AbstractTest {

    private InputStream readAndTrim(String resource)
    throws IOException {
        final String data = new String(IO.read(resource), ASCII).trim();
        return new ByteArrayInputStream(data.getBytes(ASCII));
    }

    @Test
    public void testCombiningInputStream()
    throws Exception {
        final InputStream input = new PEMCombiningInputStream(readAndTrim("chains.pem"),      // 13
                                                              readAndTrim("crl.pem"),         // 1
                                                              readAndTrim("full.pem"),        // 4
                                                              readAndTrim("selfsigned.pem")); // 2
        final PEMReader reader = new PEMReader(input);

        try {
            int count = 0;
            while (reader.read() != null) count ++;
            assertEquals(count, 20, "Wrong number of entries");
        } finally {
            reader.close();
            input.close();
        }
    }
}
