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

import java.io.File;
import java.security.GeneralSecurityException;
import java.util.AbstractSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.FileConfigurations;



public class SecureConfigurations extends Configurations {

    private final Configurations configurations;
    private final Vault vault;

    public SecureConfigurations(Configurations configurations, char[] password) {
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

    /* Utility method to encrypt/decrypt configurations */
    private static void help() {
        System.out.println("Usage: java " + SecureConfigurations.class.getName() + " [-action] filename [...]");
        System.out.println("");
        System.out.println("  Options:");
        System.out.println("    [-h|-help]           Simply display this help page");
        System.out.println("    [-e|-enc|-encrypt]   Encrypt the value specified on the command line");
        System.out.println("    [-e|-enc|-encrypt]   Encrypt the value specified on the command line");
        System.out.println("    [-d|-dec|-decrypt]   Decrypt the value associated with the specified key");
        System.out.println("    filename             The '.json' or '.properties' configuration file");
        System.out.println("");
        System.out.println("  Encryption:");
        System.out.println("    When encrypting, each value specified on the command line will be");
        System.out.println("    encrypted and echoed back on standard output.");
        System.out.println("");
        System.out.println("  Decryption:");
        System.out.println("    When decrypting, each key specified on the command line will be");
        System.out.println("    decrypted and echoed back on standard output, if no value is");
        System.out.println("    specified, the whole configuration file will be decrypted");
        System.out.println("");
        System.exit(1);
    }

    public static void main(String[] args) {
        final AtomicBoolean encrypt = new AtomicBoolean(false);
        final AtomicReference<String> filename = new AtomicReference<>();
        final List<String> actions = new ArrayList<>();

        /* Parse command line options */
        Arrays.asList(args).forEach((arg) -> {

            /* -encrypt command line option */
            if (arg.equalsIgnoreCase("-h") || arg.equalsIgnoreCase("-help")) {
                help();
            }

            /* -encrypt command line option */
            if (arg.equalsIgnoreCase("-e") || arg.equalsIgnoreCase("-enc") || arg.equalsIgnoreCase("-encrypt")) {
                encrypt.set(true);
                return;
            }

            /* -decrypt command line option */
            if (arg.equalsIgnoreCase("-d") || arg.equalsIgnoreCase("-dec") || arg.equalsIgnoreCase("-decrypt")) {
                encrypt.set(false);
                return;
            }

            /* Filename or action? */
            if (filename.get() == null) {
                filename.set(arg);
            } else {
                actions.add(arg);
            }
        });

        /* Check parameters */
        if ((filename.get() == null) || (encrypt.get() && (actions.size() == 0))) help();

        /* Load configurations */
        final Configurations base = new FileConfigurations(new File(filename.get()).getAbsoluteFile());

        /* Read password */
        final char[] password = System.console().readPassword("Password: ");

        /* Build up our secure configuration */
        final SecureConfigurations conf = new SecureConfigurations(base, password);

        /* Encrypt or decrypt? */
        if (encrypt.get()) {
            /* Encrypt each keyword */
            actions.forEach((action) -> {
                try {
                    System.out.printf("%s = %s\n", action, conf.vault.encrypt(action));
                } catch (Exception exception) {
                    System.err.println("Error encrypting string '" + action + "'");
                    exception.printStackTrace(System.err);
                    System.exit(2);
                }
            });
        } else {
            if (actions.isEmpty()) {
                actions.addAll(conf.keySet());
                Collections.sort(actions);
            }
            actions.forEach((key) -> System.err.printf("%s = %s\n", key, conf.get(key)));
        }
    }
}
