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

/**
 * An abstract implementation of the {@link HashFunction} interface.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 * @param <F> The concrete type of {@link AbstractFunction} implemented.
 */
public abstract class AbstractFunction<F extends AbstractFunction<F>>
implements HashFunction<F> {

    /* The {@link Hash} used by this function. */
    private final Hash hash;

    /**
     * Create a new {@link AbstractFunction} instance associated with the
     * specifed {@link Hash}.
     */
    protected AbstractFunction(Hash hash) {
        assert (hash != null): "Hash is null";
        this.hash = hash;
    }

    /* ====================================================================== */

    @Override
    public final Hash getHash() {
        return hash;
    }

    @Override
    public final int getHashLength() {
        return hash.getHashLength();
    }

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
