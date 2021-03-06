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

import static org.usrz.libs.utils.Charsets.UTF8;
import static org.usrz.libs.utils.codecs.HexCodec.HEX;

import java.util.Random;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.usrz.libs.testing.AbstractTest;

public class SCryptTest extends AbstractTest {

    protected boolean shouldUseNative() {
        return false;
    }

    protected final SCrypt newInstance(int iterations,
                                       int blockSize,
                                       int parallelization,
                                       int derivedKeyLength) {
        if (shouldUseNative()) {
            SCryptNativeHelper.enable();
        } else {
            SCryptNativeHelper.disable();
        }
        final SCrypt scrypt = new SCrypt(iterations, blockSize, parallelization, derivedKeyLength);
        assertEquals(scrypt.isNative(), shouldUseNative());

        return scrypt;
    }

    @BeforeClass
    public void before() {
        log.info("Tests will be running with native support %s", shouldUseNative() ? "ENABLED" : "DISABLED");
    }

    @Test
    public void testParallelThreads()
    throws InterruptedException {

        final int threadsCount = 5;
        final int testsPerThread = 20;

        /* Our structures */
        final Thread[] threads = new Thread[threadsCount];
        final byte[][] passwords = new byte[threadsCount][];
        final byte[][] salts = new byte[threadsCount][];
        final byte[][] results = new byte[threadsCount][];
        final boolean[] successes = new boolean[threadsCount];

        /* Our shared SCrypt instance */
        final SCrypt scrypt = newInstance(1024, 8, 16, 64);

        /* Randomness */
        final Random random = new Random();

        /* Create the threads */
        for (int x = 0; x < threadsCount; x ++) {
            final int index = x;

            /* Randomize password and salt */
            passwords[index] = new byte[12];
            salts[index] = new byte[16];
            random.nextBytes(passwords[index]);
            random.nextBytes(salts[index]);

            /* Calculate result */
            results[index] = scrypt.deriveKey(passwords[index], salts[index]);

            /* Create thread looping */
            threads[index] = new Thread() {
                @Override
                public void run() {
                    try {
                        for (int x = 0; x < testsPerThread; x ++) {
                            assertEquals(scrypt.deriveKey(passwords[index], salts[index]), results[index]);
                        }
                        successes[index] = true;

                    } catch (Throwable throwable) {
                        System.err.println("Thread " + index + " failed");
                        throwable.printStackTrace(System.err);
                        successes[index] = false;
                    }

                }
            };
        }

        /* Start and wait for the threads */
        for (Thread thread: threads) thread.start();
        for (Thread thread: threads) thread.join();

        /* Verify */
        for (int x = 0; x < threadsCount; x++) {
            assertTrue(successes[x], "Thread " + x + " was not successful");
        }

    }

    /* ====================================================================== */

    @Test
    public void testSpeed() {
        final SCrypt scrypt = newInstance(16384, 8, 1, 64);
        System.err.println("Computational memory per iteration: " + (scrypt.getComputationMemoryRequirement() / 1048576F) + " megs");

        final byte[] password = "pleaseletmein".getBytes(UTF8);
        final byte[] salt = "SodiumChloride".getBytes(UTF8);

        System.err.print("Running ");
        final int iterations = 20;
        final long now = System.currentTimeMillis();
        for (int x = 0; x < iterations; x ++) {
            System.err.print('.');
            scrypt.deriveKey(password, salt);
        }
        final long elapsed = System.currentTimeMillis() - now;

        System.err.println();
        System.err.println("Total " + (elapsed / 1000F) + " seconds (" + (elapsed / iterations) + " ms per iteration)");

    }

    /* ====================================================================== */

    @Test(expectedExceptions=IllegalArgumentException.class,
          expectedExceptionsMessageRegExp="^Buffer too short")
    public void testShortBuffer() {
        final byte[] result = new byte[63];

        newInstance(1024, 8, 16, 64).deriveKey("password".getBytes(UTF8), "NaCl".getBytes(UTF8), result, 0);
        assertEquals(result, HEX.decode("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"));
    }

    @Test
    public void testLongBuffer() {
        final byte[] result = new byte[66];
        result[0] = 0x29;
        result[65] = 0x1;

        newInstance(1024, 8, 16, 64).deriveKey("password".getBytes(UTF8), "NaCl".getBytes(UTF8), result, 1);
        assertEquals(result, HEX.decode("29fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc064001"));
    }

    /* ====================================================================== */
    /* Test vectors: http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01 */
    /* ====================================================================== */

    @Test
    public void testIETFVector1() {
        assertEquals(newInstance(16, 1, 1, 64).deriveKey("".getBytes(UTF8), "".getBytes(UTF8)),
                            HEX.decode("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"));
    }

    @Test
    public void testIETFVector2() {
        assertEquals(newInstance(1024, 8, 16, 64).deriveKey("password".getBytes(UTF8), "NaCl".getBytes(UTF8)),
                            HEX.decode("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"));
    }

    @Test
    public void testIETFVector3() {
        assertEquals(newInstance(16384, 8, 1, 64).deriveKey("pleaseletmein".getBytes(UTF8), "SodiumChloride".getBytes(UTF8)),
                            HEX.decode("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"));
    }

    @Test
    public void testIETFVector4() {
        assertEquals(newInstance(1048576, 8, 1, 64).deriveKey("pleaseletmein".getBytes(UTF8), "SodiumChloride".getBytes(UTF8)),
                            HEX.decode("2101cb9b6a511aaeaddbbe09cf70f881ec568d574a2ffd4dabe5ee9820adaa478e56fd8f4ba5d09ffa1c6d927c40f4c337304049e8a952fbcbf45c6fa77a41a4"));
    }

}
