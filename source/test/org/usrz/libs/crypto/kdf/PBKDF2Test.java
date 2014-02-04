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

import static org.usrz.libs.crypto.codecs.Base64Codec.BASE_64;
import static org.usrz.libs.crypto.codecs.HexCodec.HEX;

import org.testng.annotations.Test;
import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.testing.AbstractTest;

public class PBKDF2Test extends AbstractTest {

    private final byte[] password = "password".getBytes();
    private final byte[] salt = "salt".getBytes();

    @Test
    public void testSHA1() {
        /* From http://packages.python.org/passlib/lib/passlib.hash.cta_pbkdf2_sha1.html */
        byte[] salt = BASE_64.decode("oX9ZZOcNgYoAsYL.8bqxKg");
        byte[] result = new PBKDF2(Hash.SHA1, 10000).deriveKey(password, salt);
        assertEquals(result, BASE_64.decode("AU2JLf2rNxWoZxWxRCluY0u6h6c"));
    }

    @Test
    public void testSHA256_1() {
        /* From http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html */
        byte[] salt = BASE_64.decode("0ZrzXitFSGltTQnBWOsdAw");
        byte[] result = new PBKDF2(Hash.SHA256, 6400).deriveKey(password, salt);
        assertEquals(result, BASE_64.decode("Y11AchqV4b0sUisdZd0Xr97KWoymNE0LNNrnEgY4H9M"));
    }

    @Test
    public void testSHA256_2() {
        /* From http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html */
        byte[] salt = BASE_64.decode("XAuBMIYQQogxRg");
        byte[] result = new PBKDF2(Hash.SHA256, 8000).deriveKey(password, salt);
        assertEquals(result, BASE_64.decode("tRRlz8hYn63B9LYiCd6PRo6FMiunY9ozmMMI3srxeRE"));
    }

    @Test
    public void testSHA256_3() {
        /* From http://packages.python.org/passlib/lib/passlib.hash.pbkdf2_digest.html */
        byte[] salt = BASE_64.decode(".6UI/S.nXIk8jcbdHx3Fhg");
        byte[] result = new PBKDF2(Hash.SHA256, 6400).deriveKey(password, salt);
        assertEquals(result, BASE_64.decode("98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44"));
    }

    @Test
    public void testSHA512() {
        /* From http://packages.python.org/passlib/lib/passlib.hash.grub_pbkdf2_sha512.html */
        byte[] salt = HEX.decode("4483972AD2C52E1F590B3E2260795FDA9CA0B07B96FF492814CA9775F08C4B59CD1707F10B269E09B61B1E2D11729BCA8D62B7827B25B093EC58C4C1EAC23137");
        byte[] result = new PBKDF2(Hash.SHA512, 10000).deriveKey(password, salt);
        assertEquals(result, HEX.decode("DF4FCB5DD91340D6D31E33423E4210AD47C7A4DF9FA16F401663BF288C20BF973530866178FE6D134256E4DBEFBD984B652332EED3ACAED834FEA7B73CAE851D"));
    }

    /* ===================================================================== */

    @Test
    public void testRFC6070_1() throws Exception {
        byte[] result = new PBKDF2(Hash.SHA1, 1).deriveKey(password, salt);
        assertEquals(result, HEX.decode("0c60c80f961f0e71f3a9b524af6012062fe037a6"));
    }

    @Test
    public void testRFC6070_2() throws Exception {
        byte[] result = new PBKDF2(Hash.SHA1, 2).deriveKey(password, salt);
        assertEquals(result, HEX.decode("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
    }

    @Test
    public void testRFC6070_4096() throws Exception {
        byte[] result = new PBKDF2(Hash.SHA1, 4096).deriveKey(password, salt);
        assertEquals(result, HEX.decode("4b007901b765489abead49d926f721d065a429c1"));
    }

    @Test(groups="local")
    public void testRFC6070_16777216() throws Exception {
        byte[] result = new PBKDF2(Hash.SHA1, 16777216).deriveKey(password, salt);
        assertEquals(result, HEX.decode("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"));
    }

    @Test
    public void testRFC6070_LONG() throws Exception {
        byte[] password = "passwordPASSWORDpassword".getBytes();
        byte[] salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes();
        byte[] result = new PBKDF2(Hash.SHA1, 4096, 25).deriveKey(password, salt);
        assertEquals(result, HEX.decode("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"));
    }

    @Test
    public void testRFC6070_SHORT() throws Exception {
        byte[] password = "pass\0word".getBytes();
        byte[] salt = "sa\0lt".getBytes();
        byte[] result = new PBKDF2(Hash.SHA1, 4096, 16).deriveKey(password, salt);
        assertEquals(result, HEX.decode("56fa6aa75548099dcc37d7f03425e0c3"));
    }

    /* ===================================================================== */

    @Test
    public void testLongBuffer() {
        byte[] result = new byte[22];
        result[0] = 0x029;
        result[21] = 0x01;
        new PBKDF2(Hash.SHA1, 1).deriveKey(password, salt, result, 1);
        assertEquals(result, HEX.decode("290c60c80f961f0e71f3a9b524af6012062fe037a601"));
    }

    @Test(expectedExceptions=IllegalArgumentException.class,
          expectedExceptionsMessageRegExp="^Buffer too short$")
    public void testShortBuffer() {
        new PBKDF2(Hash.SHA1, 1).deriveKey(password, salt, new byte[19], 1);
    }

}
