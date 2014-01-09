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

import java.nio.charset.Charset;
import java.util.Random;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.usrz.libs.crypto.codecs.Base32Codec;

public class Base32CodecTest {

    private static byte[] convert(String string) {
        return string.getBytes(Charset.forName("UTF8"));
    }

    private static String convert(byte[] data) {
        return new String(data, Charset.forName("UTF8"));
    }

    @Test
    public void testEncode() {
        final Base32Codec base32 = new Base32Codec();

        Assert.assertEquals(base32.encode(convert("")), "");
        Assert.assertEquals(base32.encode(convert("f")), "MY");
        Assert.assertEquals(base32.encode(convert("fo")), "MZXQ");
        Assert.assertEquals(base32.encode(convert("foo")), "MZXW6");
        Assert.assertEquals(base32.encode(convert("foob")), "MZXW6YQ");
        Assert.assertEquals(base32.encode(convert("fooba")), "MZXW6YTB");
        Assert.assertEquals(base32.encode(convert("foobar")), "MZXW6YTBOI");

        Assert.assertEquals(base32.encode(convert("--"), 1, 0), "");
        Assert.assertEquals(base32.encode(convert("-f--"), 1, 1), "MY");
        Assert.assertEquals(base32.encode(convert("-fo---"), 1, 2), "MZXQ");
        Assert.assertEquals(base32.encode(convert("-foo----"), 1, 3), "MZXW6");
        Assert.assertEquals(base32.encode(convert("-foob-----"), 1, 4), "MZXW6YQ");
        Assert.assertEquals(base32.encode(convert("-fooba------"), 1, 5), "MZXW6YTB");
        Assert.assertEquals(base32.encode(convert("-foobar-------"), 1, 6), "MZXW6YTBOI");

    }

    @Test
    public void testDecode() {
        final Base32Codec base32 = new Base32Codec();

        Assert.assertEquals(convert(base32.decode("")), "");
        Assert.assertEquals(convert(base32.decode("MY")), "f");
        Assert.assertEquals(convert(base32.decode("MZXQ")), "fo");
        Assert.assertEquals(convert(base32.decode("MZXW6")), "foo");
        Assert.assertEquals(convert(base32.decode("MZXW6YQ")), "foob");
        Assert.assertEquals(convert(base32.decode("MZXW6YTB")), "fooba");
        Assert.assertEquals(convert(base32.decode("MZXW6YTBOI")), "foobar");

        Assert.assertEquals(convert(base32.decode("")), "");
        Assert.assertEquals(convert(base32.decode("my")), "f");
        Assert.assertEquals(convert(base32.decode("mzxq")), "fo");
        Assert.assertEquals(convert(base32.decode("mzxw6")), "foo");
        Assert.assertEquals(convert(base32.decode("mzxw6yq")), "foob");
        Assert.assertEquals(convert(base32.decode("mzxw6ytb")), "fooba");
        Assert.assertEquals(convert(base32.decode("mzxw6ytboi")), "foobar");

    }

    @Test
    public void testRandom() {
        final Base32Codec base32 = new Base32Codec();
        final Random random = new Random();

        for (int x = 0; x < 1000; x ++) {
            final byte[] data = new byte[random.nextInt(50) + 50];
            random.nextBytes(data);
            final String encoded = base32.encode(data);
            final byte[] decoded = base32.decode(encoded);
            Assert.assertEquals(decoded, data);
        }

    }
}
