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

import java.util.Objects;

import org.usrz.libs.crypto.hash.Hash;
import org.usrz.libs.crypto.kdf.KDF.Type;

/**
 * A basic abstract implementation of the {@link KDFSpec} interface.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public abstract class AbstractKDFSpec implements KDFSpec {

    private final Type type;
    private final Hash hash;
    private final int length;

    /**
     * Create an {@link AbstractKDFSpec} instance asspciated with the given
     * {@link Type}, {@link Hash} and <em>derived key length</em>.
     *
     * <p>If the specified {@link Hash} is <b>null</b> it will be defaulted
     * to the KDF's own {@linkplain Type#getDefaultHash() default hash}.</p>
     *
     * <p>If the specified <em>derived key length</em> is less than 1, it will
     * be defaulted to the {@linkplain Hash#getHashLength() hash length}.</p>
     */
    protected AbstractKDFSpec(Type type, Hash hash, int length) {
        this.type = Objects.requireNonNull(type, "Null KDF type");
        this.hash = hash != null ? hash : type.getDefaultHash();
        this.length = length > 0 ? length : this.hash.getHashLength();
    }

    @Override
    public final Type getType() {
        return type;
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
        return (type.hashCode() ^ hash.hashCode()) * length;
    }

    @Override
    public boolean equals(Object object) {
        if (object == this) return true;
        if (object == null) return false;
        try {
            final AbstractKDFSpec spec = (AbstractKDFSpec) object;
            return length == spec.getDerivedKeyLength()
                   && getType() == spec.getType()
                   && getHash() == spec.getHash();
        } catch (ClassCastException exception) {
            return false;
        }
    }
}
