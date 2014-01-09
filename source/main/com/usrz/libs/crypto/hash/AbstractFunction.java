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
package com.usrz.libs.crypto.hash;

public abstract class AbstractFunction<F extends AbstractFunction<F>>
implements HashFunction<F> {

    private final Hash hash;

    protected AbstractFunction(Hash hash) {
        assert (hash != null): "Hash is null";
        this.hash = hash;
    }

    @Override
    public final Hash getHash() {
        return hash;
    }

    @Override
    public final int getHashLength() {
        return hash.getHashLength();
    }

    /* ====================================================================== */

    @Override
    public final F update(byte input) {
        return update(new byte[] { input }, 0, 1);
    }

    @Override
    public final F update(byte[] input) {
        return update(input, 0, input.length);
    }

    @Override
    public final byte[] finish() {
        final byte[] result = new byte[getHashLength()];
        finish(result, 0);
        return result;
    }

}
