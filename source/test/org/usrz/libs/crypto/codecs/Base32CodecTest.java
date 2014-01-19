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

import static org.usrz.libs.crypto.codecs.CharsetCodec.UTF8;

import java.util.Random;

import org.testng.Assert;
import org.testng.annotations.Test;

public class Base32CodecTest {

    private static final CharsetCodec codec = new CharsetCodec(UTF8);

    @Test
    public void testEncode() {
        final Base32Codec base32 = new Base32Codec();

        Assert.assertEquals(base32.encode(codec.decode("")), "");
        Assert.assertEquals(base32.encode(codec.decode("f")), "MY");
        Assert.assertEquals(base32.encode(codec.decode("fo")), "MZXQ");
        Assert.assertEquals(base32.encode(codec.decode("foo")), "MZXW6");
        Assert.assertEquals(base32.encode(codec.decode("foob")), "MZXW6YQ");
        Assert.assertEquals(base32.encode(codec.decode("fooba")), "MZXW6YTB");
        Assert.assertEquals(base32.encode(codec.decode("foobar")), "MZXW6YTBOI");

        Assert.assertEquals(base32.encode(codec.decode("--"), 1, 0), "");
        Assert.assertEquals(base32.encode(codec.decode("-f--"), 1, 1), "MY");
        Assert.assertEquals(base32.encode(codec.decode("-fo---"), 1, 2), "MZXQ");
        Assert.assertEquals(base32.encode(codec.decode("-foo----"), 1, 3), "MZXW6");
        Assert.assertEquals(base32.encode(codec.decode("-foob-----"), 1, 4), "MZXW6YQ");
        Assert.assertEquals(base32.encode(codec.decode("-fooba------"), 1, 5), "MZXW6YTB");
        Assert.assertEquals(base32.encode(codec.decode("-foobar-------"), 1, 6), "MZXW6YTBOI");

    }

    @Test
    public void testDecode() {
        final Base32Codec base32 = new Base32Codec();

        Assert.assertEquals(codec.encode(base32.decode("")), "");
        Assert.assertEquals(codec.encode(base32.decode("MY")), "f");
        Assert.assertEquals(codec.encode(base32.decode("MZXQ")), "fo");
        Assert.assertEquals(codec.encode(base32.decode("MZXW6")), "foo");
        Assert.assertEquals(codec.encode(base32.decode("MZXW6YQ")), "foob");
        Assert.assertEquals(codec.encode(base32.decode("MZXW6YTB")), "fooba");
        Assert.assertEquals(codec.encode(base32.decode("MZXW6YTBOI")), "foobar");

        Assert.assertEquals(codec.encode(base32.decode("")), "");
        Assert.assertEquals(codec.encode(base32.decode("my")), "f");
        Assert.assertEquals(codec.encode(base32.decode("mzxq")), "fo");
        Assert.assertEquals(codec.encode(base32.decode("mzxw6")), "foo");
        Assert.assertEquals(codec.encode(base32.decode("mzxw6yq")), "foob");
        Assert.assertEquals(codec.encode(base32.decode("mzxw6ytb")), "fooba");
        Assert.assertEquals(codec.encode(base32.decode("mzxw6ytboi")), "foobar");

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
