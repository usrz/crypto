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

import org.testng.annotations.Test;

public class SCryptNativeTest extends SCryptTest {

    @Override
    protected boolean shouldUseNative() {
        return true;
    }

    @Override @Test
    public void testParallelThreads()
    throws InterruptedException {
        super.testParallelThreads();
    }

    @Override @Test
    public void testSpeed() {
        super.testSpeed();
    }

    @Override
    @Test(expectedExceptions=IllegalArgumentException.class,
          expectedExceptionsMessageRegExp="^Buffer too short")
    public void testShortBuffer() {
        super.testShortBuffer();
    }

    @Override @Test
    public void testLongBuffer() {
        super.testLongBuffer();
    }

    @Override @Test
    public void testIETFVector1() {
        super.testIETFVector1();
    }

    @Override @Test
    public void testIETFVector2() {
        super.testIETFVector2();
    }

    @Override @Test
    public void testIETFVector3() {
        super.testIETFVector3();
    }

    @Override @Test
    public void testIETFVector4() {
        super.testIETFVector4();
    }

}
