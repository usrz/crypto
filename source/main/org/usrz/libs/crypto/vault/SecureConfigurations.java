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
package org.usrz.libs.crypto.vault;

import java.security.GeneralSecurityException;
import java.util.AbstractSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

import org.usrz.libs.configurations.Configurations;

public class SecureConfigurations extends Configurations {

    private final Configurations configurations;
    private final Vault vault;

    public SecureConfigurations(Configurations configurations, Vault vault) {
        this.configurations = Objects.requireNonNull(configurations, "Null configurations");
        this.vault = Objects.requireNonNull(vault, "Null vault");
    }

    @Override
    public String getString(Object key, String defaultValue) {
        final String value = configurations.getString(key);
        if (value == null) return defaultValue;
        try {
            return vault.decode(value);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to decrypt \"" + key + "\"", exception);
        }
    }

    @Override
    public Set<Entry<String, String>> entrySet() {
        final Set<Entry<String, String>> set = configurations.entrySet();
        return new AbstractSet<Entry<String, String>>() {

            @Override
            public Iterator<Entry<String, String>> iterator() {
                final Iterator<Entry<String, String>> iterator = set.iterator();
                return new Iterator<Entry<String, String>>() {

                    @Override
                    public boolean hasNext() {
                        return iterator.hasNext();
                    }

                    @Override
                    public Entry<String, String> next() {
                        final Entry<String, String> entry = iterator.next();
                        return new Entry<String, String>() {

                            @Override
                            public String getKey() {
                                return entry.getKey();
                            }

                            @Override
                            public String getValue() {
                                try {
                                    return vault.decode(entry.getValue());
                                } catch (GeneralSecurityException exception) {
                                    throw new IllegalStateException("Unable to decrypt \"" + getKey() + "\"", exception);
                                }
                            }

                            @Override
                            public String setValue(String value) {
                                throw new UnsupportedOperationException();
                            }
                        };
                    }
                };
            }

            @Override
            public int size() {
                return set.size();
            }
        };
    }

    @Override
    public int size() {
        return configurations.size();
    }

}
