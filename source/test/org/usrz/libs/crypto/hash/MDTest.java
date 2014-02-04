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
package org.usrz.libs.crypto.hash;

import static org.usrz.libs.crypto.codecs.HexCodec.HEX;

import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;

public class MDTest extends AbstractTest {

    private static final byte[] DATA = "The quick brown fox jumps over the lazy dog".getBytes();

    /* ====================================================================== */

    @Test
    public void testEmptyMD5() throws Exception {
        final byte[] expected = HEX.decode("d41d8cd98f00b204e9800998ecf8427e");
        final byte[] result = Hash.MD5.digest().finish();
        assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA1() {
        final byte[] expected = HEX.decode("da39a3ee5e6b4b0d3255bfef95601890afd80709");
        final byte[] result = Hash.SHA1.digest().finish();
        assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA256() throws Exception {
        final byte[] expected = HEX.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        final byte[] result = Hash.SHA256.digest().finish();
        assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA384() {
        final byte[] expected = HEX.decode("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        final byte[] result = Hash.SHA384.digest().finish();
        assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA512() {
        final byte[] expected = HEX.decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        final byte[] result = Hash.SHA512.digest().finish();
        assertEquals(result, expected);
    }

    /* ====================================================================== */

    @Test
    public void testSimpleMD5() throws Exception {
        final byte[] expected = HEX.decode("9e107d9d372bb6826bd81d3542a419d6");
        final byte[] result = Hash.MD5.digest().update(DATA).finish();
        assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA1() {
        final byte[] expected = HEX.decode("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
        final byte[] result = Hash.SHA1.digest().update(DATA).finish();
        assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA256() throws Exception {
        final byte[] expected = HEX.decode("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
        final byte[] result = Hash.SHA256.digest().update(DATA).finish();
        assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA384() {
        final byte[] expected = HEX.decode("ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1");
        final byte[] result = Hash.SHA384.digest().update(DATA).finish();
        assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA512() {
        final byte[] expected = HEX.decode("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
        final byte[] result = Hash.SHA512.digest().update(DATA).finish();
        assertEquals(result, expected);
    }

    /* ====================================================================== */

    @Test(expectedExceptions=IllegalArgumentException.class,
          expectedExceptionsMessageRegExp="^Buffer too short")
    public void testShortMD5() {
        final byte[] result = new byte[Hash.MD5.getHashLength() - 1];
        Hash.MD5.digest().update(DATA).finish(result, 0);
    }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA1() {
          final byte[] result = new byte[Hash.SHA1.getHashLength() - 1];
          Hash.SHA1.digest().update(DATA).finish(result, 0);
      }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA256() {
          final byte[] result = new byte[Hash.SHA256.getHashLength() - 1];
          Hash.SHA256.digest().update(DATA).finish(result, 0);
      }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA384() {
          final byte[] result = new byte[Hash.SHA256.getHashLength() - 1];
          Hash.SHA256.digest().update(DATA).finish(result, 0);
      }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA512() {
          final byte[] result = new byte[Hash.SHA512.getHashLength() - 1];
          Hash.SHA512.digest().update(DATA).finish(result, 0);
      }
}
