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

import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.crypto.kdf.KDF.Function;
import org.usrz.libs.utils.Check;

/**
 * A basic abstract implementation of the {@link KDFSpec} interface.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public abstract class AbstractKDFSpec implements KDFSpec {

    private final Function function;
    private final Hash hash;
    private final int length;

    /**
     * Create an {@link AbstractKDFSpec} instance asspciated with the given
     * {@link Function}, {@link Hash} and <em>derived key length</em>.
     *
     * <p>If the specified {@link Hash} is <b>null</b> it will be defaulted
     * to the KDF's own {@linkplain Function#getDefaultHash() default hash}.</p>
     *
     * <p>If the specified <em>derived key length</em> is less than 1, it will
     * be defaulted to the {@linkplain Hash#getHashLength() hash length}.</p>
     */
    protected AbstractKDFSpec(Function function, Hash hash, int length) {
        this.function = Check.notNull(function, "Null KDF function");
        this.hash = hash != null ? hash : function.getDefaultHash();
        this.length = length > 0 ? length : this.hash.getHashLength();
    }

    @Override
    public final Function getFunction() {
        return function;
    }

    @Override
    public final Hash getHash() {
        return hash;
    }

    @Override
    public final int getDerivedKeyLength() {
        return length;
    }

    @Override
    public int hashCode() {
        return (function.hashCode() ^ hash.hashCode()) * length;
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) return true;
        if (object == null) return false;
        try {
            final AbstractKDFSpec spec = (AbstractKDFSpec) object;
            return length == spec.getDerivedKeyLength()
                   && getFunction() == spec.getFunction()
                   && getHash() == spec.getHash();
        } catch (ClassCastException exception) {
            return false;
        }
    }
}
