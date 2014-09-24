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

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;
import org.usrz.libs.utils.Charsets;

public class CryptoUtilsTest extends AbstractTest {

    @Test
    public void testSafeDecode() {
        final byte[] bytes = "\u6771\u4EAC".getBytes(Charsets.UTF8);
        final char[] chars = CryptoUtils.safeDecode(bytes, false);
        assertEquals(chars, "\u6771\u4EAC".toCharArray());
        assertEquals(bytes, "\u6771\u4EAC".getBytes(Charsets.UTF8));
    }

    @Test
    public void testSafeDecodeAndDestroy() {
        final byte[] bytes = "\u6771\u4EAC".getBytes(Charsets.UTF8);
        final char[] chars = CryptoUtils.safeDecode(bytes, true);
        assertEquals(chars, "\u6771\u4EAC".toCharArray());
        assertNotEquals(bytes, "\u6771\u4EAC".getBytes(Charsets.UTF8), "Not wiped");
        for (byte b: bytes) assertEquals(b, 0, "Should be all zeroes...");
    }

    @Test
    public void testSafeEncode() {
        final char[] chars = "\u6771\u4EAC".toCharArray();
        final byte[] bytes = CryptoUtils.safeEncode(chars, false);
        assertEquals(bytes, "\u6771\u4EAC".getBytes(Charsets.UTF8));
        assertEquals(chars, "\u6771\u4EAC".toCharArray());
    }

    @Test
    public void testSafeEncodeAndDestroy() {
        final char[] chars = "\u6771\u4EAC".toCharArray();
        final byte[] bytes = CryptoUtils.safeEncode(chars, true);
        assertEquals(bytes, "\u6771\u4EAC".getBytes(Charsets.UTF8));
        assertNotEquals(chars, "\u6771\u4EAC".toCharArray(), "Not wiped");
        for (char c: chars) assertEquals(c, 0, "Should be all zeroes...");
    }

}
