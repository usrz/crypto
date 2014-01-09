package com.usrz.libs.crypto.hash;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.usrz.libs.crypto.codecs.HexCodec;

public class HMACTest {

    private static final byte[] KEY = "Jefe".getBytes();
    private static final byte[] DATA = "what do ya want for nothing?".getBytes();

    /* ====================================================================== */

    @Test
    public void testEmptyMD5() throws Exception {
        final byte[] expected = new HexCodec().decode("74e6f7298a9c2d168935f58c001bad88");
        final byte[] result = Hash.MD5.hmac(null).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA1() {
        final byte[] expected = new HexCodec().decode("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
        final byte[] result = Hash.SHA1.hmac(null).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA256() throws Exception {
        final byte[] expected = new HexCodec().decode("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
        final byte[] result = Hash.SHA256.hmac(null).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA384() {
        final byte[] expected = new HexCodec().decode("6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc");
        final byte[] result = Hash.SHA384.hmac(null).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testEmptySHA512() {
        final byte[] expected = new HexCodec().decode("b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47");
        final byte[] result = Hash.SHA512.hmac(null).finish();
        Assert.assertEquals(result, expected);
    }

    /* ====================================================================== */

    @Test
    public void testSimpleMD5() {
        final byte[] expected = new HexCodec().decode("750c783e6ab0b503eaa86e310a5db738");
        final byte[] result = Hash.MD5.hmac(KEY).update(DATA).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA1() {
        final byte[] expected = new HexCodec().decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        final byte[] result = Hash.SHA1.hmac(KEY).update(DATA).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA256() {
        final byte[] expected = new HexCodec().decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        final byte[] result = Hash.SHA256.hmac(KEY).update(DATA).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA384() {
        final byte[] expected = new HexCodec().decode("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
        final byte[] result = Hash.SHA384.hmac(KEY).update(DATA).finish();
        Assert.assertEquals(result, expected);
    }

    @Test
    public void testSimpleSHA512() {
        final byte[] expected = new HexCodec().decode("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
        final byte[] result = Hash.SHA512.hmac(KEY).update(DATA).finish();
        Assert.assertEquals(result, expected);
    }

    /* ====================================================================== */

    @Test(expectedExceptions=IllegalArgumentException.class,
          expectedExceptionsMessageRegExp="^Buffer too short")
    public void testShortMD5() {
        final byte[] result = new byte[Hash.MD5.getHashLength() - 1];
        Hash.MD5.hmac(KEY).update(DATA).finish(result, 0);
    }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA1() {
          final byte[] result = new byte[Hash.SHA1.getHashLength() - 1];
          Hash.SHA1.hmac(KEY).update(DATA).finish(result, 0);
      }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA256() {
          final byte[] result = new byte[Hash.SHA256.getHashLength() - 1];
          Hash.SHA256.hmac(KEY).update(DATA).finish(result, 0);
      }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA384() {
          final byte[] result = new byte[Hash.SHA256.getHashLength() - 1];
          Hash.SHA256.hmac(KEY).update(DATA).finish(result, 0);
      }

    @Test(expectedExceptions=IllegalArgumentException.class,
            expectedExceptionsMessageRegExp="^Buffer too short")
      public void testShortSHA512() {
          final byte[] result = new byte[Hash.SHA512.getHashLength() - 1];
          Hash.SHA512.hmac(KEY).update(DATA).finish(result, 0);
      }

}
