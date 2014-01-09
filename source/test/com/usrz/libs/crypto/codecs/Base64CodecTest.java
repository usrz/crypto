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
package com.usrz.libs.crypto.codecs;

import java.nio.charset.Charset;

import org.testng.Assert;
import org.testng.annotations.Test;

public class Base64CodecTest {

    private final Charset UTF8 = Charset.forName("UTF-8");

    @Test
    public void testSimpleEncode() {
        byte array[] = new byte[] { (byte) 0x00, (byte) 0x10, (byte) 0x83, (byte) 0x10,
                                    (byte) 0x51, (byte) 0x87, (byte) 0x20, (byte) 0x92,
                                    (byte) 0x8b, (byte) 0x30, (byte) 0xd3, (byte) 0x8f,
                                    (byte) 0x41, (byte) 0x14, (byte) 0x93, (byte) 0x51,
                                    (byte) 0x55, (byte) 0x97, (byte) 0x61, (byte) 0x96,
                                    (byte) 0x9b, (byte) 0x71, (byte) 0xd7, (byte) 0x9f,
                                    (byte) 0x82, (byte) 0x18, (byte) 0xa3, (byte) 0x92,
                                    (byte) 0x59, (byte) 0xa7, (byte) 0xa2, (byte) 0x9a,
                                    (byte) 0xab, (byte) 0xb2, (byte) 0xdb, (byte) 0xaf,
                                    (byte) 0xc3, (byte) 0x1c, (byte) 0xb3, (byte) 0xd3,
                                    (byte) 0x5d, (byte) 0xb7, (byte) 0xe3, (byte) 0x9e,
                                    (byte) 0xbb, (byte) 0xf3, (byte) 0xdf, (byte) 0xbf };
        String string = new Base64Codec().encode(array);
        Assert.assertEquals(string, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    }

    @Test
    public void testSimpleDecode() {
        byte array[] = new byte[] { (byte) 0x00, (byte) 0x10, (byte) 0x83, (byte) 0x10,
                                    (byte) 0x51, (byte) 0x87, (byte) 0x20, (byte) 0x92,
                                    (byte) 0x8b, (byte) 0x30, (byte) 0xd3, (byte) 0x8f,
                                    (byte) 0x41, (byte) 0x14, (byte) 0x93, (byte) 0x51,
                                    (byte) 0x55, (byte) 0x97, (byte) 0x61, (byte) 0x96,
                                    (byte) 0x9b, (byte) 0x71, (byte) 0xd7, (byte) 0x9f,
                                    (byte) 0x82, (byte) 0x18, (byte) 0xa3, (byte) 0x92,
                                    (byte) 0x59, (byte) 0xa7, (byte) 0xa2, (byte) 0x9a,
                                    (byte) 0xab, (byte) 0xb2, (byte) 0xdb, (byte) 0xaf,
                                    (byte) 0xc3, (byte) 0x1c, (byte) 0xb3, (byte) 0xd3,
                                    (byte) 0x5d, (byte) 0xb7, (byte) 0xe3, (byte) 0x9e,
                                    (byte) 0xbb, (byte) 0xf3, (byte) 0xdf, (byte) 0xbf };
        byte result[] = new Base64Codec().decode("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
        Assert.assertEquals(result, array);
    }

    @Test
    public void testDecodeDictionary() {
        Assert.assertEquals(new Base64Codec().decode("YQ"),              "a".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWI"),             "ab".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJj"),            "abc".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZA"),          "abcd".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGU"),         "abcde".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVm"),        "abcdef".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZw"),      "abcdefg".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2g"),     "abcdefgh".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2hp"),    "abcdefghi".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2hpag"),  "abcdefghij".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2hpams"), "abcdefghijk".getBytes(UTF8));
    }

    @Test
    public void testEncodeDictionary() {
        Assert.assertEquals(new Base64Codec(false).encode("a".getBytes(UTF8)),           "YQ");
        Assert.assertEquals(new Base64Codec(false).encode("ab".getBytes(UTF8)),          "YWI");
        Assert.assertEquals(new Base64Codec(false).encode("abc".getBytes(UTF8)),         "YWJj");
        Assert.assertEquals(new Base64Codec(false).encode("abcd".getBytes(UTF8)),        "YWJjZA");
        Assert.assertEquals(new Base64Codec(false).encode("abcde".getBytes(UTF8)),       "YWJjZGU");
        Assert.assertEquals(new Base64Codec(false).encode("abcdef".getBytes(UTF8)),      "YWJjZGVm");
        Assert.assertEquals(new Base64Codec(false).encode("abcdefg".getBytes(UTF8)),     "YWJjZGVmZw");
        Assert.assertEquals(new Base64Codec(false).encode("abcdefgh".getBytes(UTF8)),    "YWJjZGVmZ2g");
        Assert.assertEquals(new Base64Codec(false).encode("abcdefghi".getBytes(UTF8)),   "YWJjZGVmZ2hp");
        Assert.assertEquals(new Base64Codec(false).encode("abcdefghij".getBytes(UTF8)),  "YWJjZGVmZ2hpag");
        Assert.assertEquals(new Base64Codec(false).encode("abcdefghijk".getBytes(UTF8)), "YWJjZGVmZ2hpams");
    }

    @Test
    public void testDecodePadding() {
        Assert.assertEquals(new Base64Codec().decode("YQ=="),             "a".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWI="),             "ab".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJj"),             "abc".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZA=="),         "abcd".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGU="),         "abcde".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVm"),         "abcdef".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZw=="),     "abcdefg".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2g="),     "abcdefgh".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2hp"),     "abcdefghi".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2hpag=="), "abcdefghij".getBytes(UTF8));
        Assert.assertEquals(new Base64Codec().decode("YWJjZGVmZ2hpams="), "abcdefghijk".getBytes(UTF8));
    }

    @Test
    public void testEncodePadding() {
        Assert.assertEquals(new Base64Codec(true).encode("a".getBytes(UTF8)),           "YQ==");
        Assert.assertEquals(new Base64Codec(true).encode("ab".getBytes(UTF8)),          "YWI=");
        Assert.assertEquals(new Base64Codec(true).encode("abc".getBytes(UTF8)),         "YWJj");
        Assert.assertEquals(new Base64Codec(true).encode("abcd".getBytes(UTF8)),        "YWJjZA==");
        Assert.assertEquals(new Base64Codec(true).encode("abcde".getBytes(UTF8)),       "YWJjZGU=");
        Assert.assertEquals(new Base64Codec(true).encode("abcdef".getBytes(UTF8)),      "YWJjZGVm");
        Assert.assertEquals(new Base64Codec(true).encode("abcdefg".getBytes(UTF8)),     "YWJjZGVmZw==");
        Assert.assertEquals(new Base64Codec(true).encode("abcdefgh".getBytes(UTF8)),    "YWJjZGVmZ2g=");
        Assert.assertEquals(new Base64Codec(true).encode("abcdefghi".getBytes(UTF8)),   "YWJjZGVmZ2hp");
        Assert.assertEquals(new Base64Codec(true).encode("abcdefghij".getBytes(UTF8)),  "YWJjZGVmZ2hpag==");
        Assert.assertEquals(new Base64Codec(true).encode("abcdefghijk".getBytes(UTF8)), "YWJjZGVmZ2hpams=");
    }

    @Test(enabled=false)
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
                byte result[] = new Base64Codec().decode(new Base64Codec().encode(array));
                Assert.assertEquals(result, array);
                count ++;
            }
        }
        System.err.println("Ran " + count + " iterations in " + (System.currentTimeMillis() - time) + " milliseconds");
    }

}
