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
package org.usrz.libs.crypto.codecs;

import org.testng.Assert;
import org.testng.annotations.Test;

public class HexCodecTest {

    @Test
    public void testEncodeAll() {
        byte[] bytes = new byte[256];
        StringBuilder builder = new StringBuilder();
        for (int x = -128; x < 128; x++) {
            bytes[x + 128] = (byte) x;
            if ((x & 0x0ff) <= 0x0f) builder.append('0');
            builder.append(Integer.toHexString(x & 0x0ff).toUpperCase());
        }
        String encoded = new HexCodec().encode(bytes);
        Assert.assertEquals(encoded, builder.toString());
    }

    @Test
    public void testReEncode() {
        byte[] bytes = new byte[256];
        for (int x = -128; x < 128; x++) {
            bytes[x + 128] = (byte) x;
        }
        byte[] result = new HexCodec().decode(new HexCodec().encode(bytes));
        Assert.assertEquals(result, bytes);
    }

    @Test
    public void testDecodeUpper() {
        byte[] bytes = new byte[256];
        StringBuilder builder = new StringBuilder();
        for (int x = -128; x < 128; x++) {
            bytes[x + 128] = (byte) x;
            if ((x & 0x0ff) <= 0x0f) builder.append('0');
            builder.append(Integer.toHexString(x & 0x0ff).toUpperCase());
        }
        byte[] decoded = new HexCodec().decode(builder.toString());
        Assert.assertEquals(decoded, bytes);
    }

    @Test
    public void testDecodeLower() {
        byte[] bytes = new byte[256];
        StringBuilder builder = new StringBuilder();
        for (int x = -128; x < 128; x++) {
            bytes[x + 128] = (byte) x;
            if ((x & 0x0ff) <= 0x0f) builder.append('0');
            builder.append(Integer.toHexString(x & 0x0ff).toUpperCase());
        }
        byte[] decoded = new HexCodec().decode(builder.toString());
        Assert.assertEquals(decoded, bytes);
    }

    @Test
    public void testReDecode() {
        StringBuilder builder = new StringBuilder();
        for (int x = -128; x < 128; x++) {
            if ((x & 0x0ff) <= 0x0f) builder.append('0');
            builder.append(Integer.toHexString(x & 0x0ff).toUpperCase());
        }
        String data = builder.toString();
        String result = new HexCodec().encode(new HexCodec().decode(data));
        Assert.assertEquals(result, data);
    }

    @Test(expectedExceptions=IllegalArgumentException.class)
    public void testDecodeWrongLength() {
        new HexCodec().decode("000");
    }

    @Test(expectedExceptions=IllegalArgumentException.class)
    public void testDecodeWrongCharacter() {
        new HexCodec().decode("FFFX");
    }

    @Test(expectedExceptions=IllegalArgumentException.class)
    public void testDecodeUnicodeCharacter() {
        new HexCodec().decode("FFF\u3041");
    }

    @Test(groups="local")
    public void testIteratively() {
        long time = System.currentTimeMillis();
        long count = 0;
        for (int length = 1; length <= 512; length ++) {
            for (int start = Byte.MIN_VALUE; start <= Byte.MAX_VALUE; start ++) {

                /* Create an array of length varying from 1 to 256 bytes */
                byte array[] = new byte[length];
                /* Populate the array starting at byte (from 0 to 255) */
                byte current = (byte) start;
                for (int x = 0; x < array.length; x ++) {
                    array[x] = current ++;
                }

                /* Encode and decode the array, it should yeld the same result */
                byte result[] = new HexCodec().decode(new HexCodec().encode(array));
                Assert.assertEquals(result, array);
                count ++;
            }
        }
        System.err.println("Ran " + count + " iterations in " + (System.currentTimeMillis() - time) + " milliseconds");
    }
}
