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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

import org.usrz.libs.configurations.Configurations;

public class SecureConfigurations extends Configurations {

    private final Configurations configurations;
    private final Vault vault;

    public SecureConfigurations(Configurations configurations, String password) {
        final VaultBuilder builder = new VaultBuilder(configurations.strip("$encryption"));
        vault = builder.withPassword(password).build();
        this.configurations = configurations;
    }

    public SecureConfigurations(Configurations configurations, Vault vault) {
        this.configurations = Objects.requireNonNull(configurations, "Null configurations");
        this.vault = Objects.requireNonNull(vault, "Null vault");
    }

    @Override
    public String getString(Object key, String defaultValue) {

        /* Check if we have an un-encrypted value */
        final String encrypted = configurations.getString(key + ".$encrypted");
        if (encrypted == null) return configurations.getString(key, defaultValue);

        /* We have an encrypted value, try to descrypt it */
        try {
            return vault.decode(encrypted);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to decrypt \"" + key + "\"", exception);
        }
    }

    @Override
    public Set<Entry<String, String>> entrySet() {

        final Set<String> keys = new HashSet<>();
        configurations.keySet().forEach((key) -> {
            if (! key.startsWith("$encryption.")) {
                keys.add(key.endsWith(".$encrypted")
                         ? key.substring(0,  key.length() - 11)
                         : key);
            }
        });

        return new AbstractSet<Entry<String, String>>() {

            @Override
            public Iterator<Entry<String, String>> iterator() {
                final Iterator<String> iterator = keys.iterator();
                return new Iterator<Entry<String, String>>() {

                    @Override
                    public boolean hasNext() {
                        return iterator.hasNext();
                    }

                    @Override
                    public Entry<String, String> next() {
                        final String key = iterator.next();
                        return new Entry<String, String>() {

                            @Override
                            public String getKey() {
                                return key;
                            }

                            @Override
                            public String getValue() {
                                return SecureConfigurations.this.getString(key);
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
                return keys.size();
            }
        };
    }

    @Override
    public int size() {
        return configurations.size();
    }

}
