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

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;

import org.usrz.libs.configurations.Configurations;
import org.usrz.libs.configurations.FileConfigurations;
import org.usrz.libs.configurations.JsonConfigurations;
import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.logging.Log;
import org.usrz.libs.utils.Check;

import com.fasterxml.jackson.databind.ObjectMapper;

public final class SecureConfigurations extends Configurations
implements ClosingDestroyable {

    private static final Log log = new Log(SecureConfigurations.class);
    public static final String PREFIX = "$encryption.";
    public static final String SUFFIX = ".$encrypted";

    private final Set<Closeable> closeables = new HashSet<>();
    private final Set<String> encryptedKeys = new HashSet<>();
    private final Set<String> plainKeys = new HashSet<>();

    private final Configurations configurations;
    private final boolean lenient;
    private final Vault vault;

    public SecureConfigurations(Configurations configurations) {
        this(null, true, configurations);
    }

    public SecureConfigurations(Configurations configurations, Password password) {
        this(configurations, password, false);
    }

    public SecureConfigurations(Configurations configurations, Vault vault) {
        this(Check.notNull(vault, "Null vault"), false, configurations);
    }

    public SecureConfigurations(Configurations configurations, Password password, boolean lenient) {
        this(new VaultBuilder(configurations.strip(PREFIX)).withPassword(password).build(),
             lenient, configurations);
    }

    public SecureConfigurations(Configurations configurations, Vault vault, boolean lenient) {
        this(Check.notNull(vault, "Null vault"), lenient, configurations);
    }

    /* ---------------------------------------------------------------------- */

    private SecureConfigurations(Vault vault, boolean lenient, Configurations configurations) {
        this.configurations = Check.notNull(configurations, "Null configurations");
        this.vault = vault; // it can be null here, checked above!
        this.lenient = lenient;

        /* Validate all our keys */
        configurations.keySet().forEach((key) -> {
            if (key.startsWith(PREFIX)) return;
            if (key.endsWith(SUFFIX)) {
                encryptedKeys.add(key.substring(0, key.length() - SUFFIX.length()));
            } else {
                plainKeys.add(key);
            }
        });

        final Set<String> intersection = new HashSet<>(plainKeys);
        intersection.retainAll(encryptedKeys);
        if (!intersection.isEmpty()) {
            throw new IllegalStateException("Some keys are both available in encrypted and decrypted format: " + intersection);
        }

        /* Check that we can decrypt all our configurations */
        encryptedKeys.forEach((key) -> {
            try {
                getPassword(key).close();
            } catch (Exception exception) {
                throw new IllegalStateException("Some keys failed to decrypt", exception);
            }
        });
    }

    /* ====================================================================== */

    @Override
    protected Configurations wrap(Map<?, ?> map) {
        final Configurations configurations = super.wrap(map);
        final SecureConfigurations secure = new SecureConfigurations(vault, lenient, configurations);
        closeables.add(secure);
        return secure;
    }

    /* ====================================================================== */
    /* Override default methods from Closeable/Destroyable                    */
    /* ====================================================================== */

    @Override
    public void close() {
        for (Closeable closeable: closeables) try {
            closeable.close();
        } catch (Exception exception) {
            log.warn(exception, "Exception closing/destroying " + closeable);
        }
        if (vault != null) vault.close();
    }


    @Override
    public boolean isDestroyed() {
        return vault == null ? false : vault.isDestroyed();
    }

    /* ====================================================================== */
    /* getString(key, default) and getPassword(key) implementation            */
    /* ====================================================================== */

    @Override
    public boolean containsKey(Object key) {
        return encryptedKeys.contains(key) || plainKeys.contains(key);
    }

    @Override
    public String getString(Object key, String defaultValue) {
        /* If we have a plain value, just return its value */
        if (plainKeys.contains(key)) return configurations.getString(key);

        /* If we have an encrypted value, return a string only if lenient */
        if (encryptedKeys.contains(key)) {
            if (lenient) return new String(getPassword(key).get());
            throw new IllegalStateException("Unable to retrieve encrypted value for \"" + key + "\" (not lenient)");
        }

        /* We don't have either, just return the default */
        return defaultValue;
    }

    @Override
    public Password getPassword(Object key) {

        /* If we have an encrypted value, wrap it in a Password */
        if (encryptedKeys.contains(key)) try {
            if (vault == null) throw new IllegalStateException("Unable to decrypt key \"" + key + "\"");
            final String encryptedKey = key.toString() + SUFFIX;
            final String encryptedValue = configurations.getString(encryptedKey);
            final Password password = vault.decryptPassword(encryptedValue);
            closeables.add(password);
            return password;
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to decrypt encrypted value for \"" + key + "\"");
        }

        /* If we have a plain value, wrap it in a Password only if lenient */
        if (plainKeys.contains(key)) {
            if (lenient) return new Password(configurations.get(key).toCharArray());
            throw new IllegalStateException("Unable to retrieve plain value for \"" + key + "\" (not lenient)");
        }

        /* If we have neither, just return null */
        return null;
    }

    /* ====================================================================== */
    /* size() and entrySet() implementation                                   */
    /* ====================================================================== */

    @Override
    public int size() {
        return configurations.size();
    }

    @Override
    public Set<Entry<String, String>> entrySet() {
        return configurations.entrySet();
    }

    /* ====================================================================== */
    /* Command line implementation                                            */
    /* ====================================================================== */

    /* Utility method to encrypt/decrypt configurations */
    private static void help() {
        System.err.println("Usage: java " + SecureConfigurations.class.getName() + " [-action] filename [..keys..]");
        System.err.println("");
        System.err.println("  Options:");
        System.err.println("    [-h|-help]            Simply display this help page");
        System.err.println("    [-e|-enc|-encrypt]    Encrypt a value to be added to the configurations");
        System.err.println("    [-d|-dec|-decrypt]    Decrypt the value associated with the specified key");
        System.err.println("    [-n|-norm|-normalize] Verify and normalize the specified configuration");
        System.err.println("    filename              The '.json' or '.properties' configuration file");
        System.err.println("");
        System.err.println("  Encryption:");
        System.err.println("    When encrypting, each value specified on the command line will be");
        System.err.println("    encrypted and echoed back on standard output.");
        System.err.println("");
        System.err.println("  Decryption:");
        System.err.println("    When decrypting, each key specified on the command line will be");
        System.err.println("    decrypted and echoed back on standard output, if no value is");
        System.err.println("    specified, the whole configuration file will be decrypted");
        System.err.println("");
        System.exit(1);
    }

    private static enum Operation { ENCRYPT, DECRYPT, NORMALIZE }

    public static void main(String[] args) {
        final AtomicReference<Operation> operation = new AtomicReference<>();
        final AtomicReference<String> filename = new AtomicReference<>();
        final List<String> keys = new ArrayList<>();

        /* Parse command line options */
        Arrays.asList(args).forEach((arg) -> {

            /* -encrypt command line option */
            if (arg.equalsIgnoreCase("-h") || arg.equalsIgnoreCase("-help")) {
                help();
            }

            /* -encrypt command line option */
            if (arg.equalsIgnoreCase("-e") || arg.equalsIgnoreCase("-enc") || arg.equalsIgnoreCase("-encrypt")) {
                operation.set(Operation.ENCRYPT);
                return;
            }

            /* -decrypt command line option */
            if (arg.equalsIgnoreCase("-d") || arg.equalsIgnoreCase("-dec") || arg.equalsIgnoreCase("-decrypt")) {
                operation.set(Operation.DECRYPT);
                return;
            }

            /* -normalize command line option */
            if (arg.equalsIgnoreCase("-n") || arg.equalsIgnoreCase("-norm") || arg.equalsIgnoreCase("-normalize")) {
                operation.set(Operation.NORMALIZE);
                return;
            }

            /* Filename or action? */
            if (filename.get() == null) {
                filename.set(arg);
            } else {
                keys.add(arg);
            }
        });

        /* Check parameters */
        if (filename.get() == null) help();
        if (operation.get() == null) help();

        /* Load configurations */
        final Configurations base = new FileConfigurations(new File(filename.get()).getAbsoluteFile());

        /* Read password, build configurations and destroy */
        final Password password = new Password(System.console().readPassword("Password: "));
        final SecureConfigurations secure = new SecureConfigurations(base, password, true);
        System.out.println();
        password.close();

        /* Encrypt or decrypt? */
        switch (operation.get()) {
            case ENCRYPT:

                /* Read from console and encrypt whatever we have to */
                final Password decrypted = new Password(System.console().readPassword("Data to encrypt: "));
                try {
                    final String key = keys.isEmpty() ? "..." : keys.get(0);
                    System.out.printf("%s%s = %s\n", key, SUFFIX, secure.vault.encryptPassword(decrypted));
                } catch (Exception exception) {
                    System.err.println("Error encrypting");
                    exception.printStackTrace(System.err);
                    System.exit(2);
                } finally {
                    decrypted.close();
                }

                break;

            case DECRYPT:

                if (keys.isEmpty()) {
                    secure.list(System.out);
                } else {
                    keys.forEach((key) -> System.out.printf("%s = %s\n", key, secure.get(key)));
                }

                break;

            case NORMALIZE:
                try {
                    /* Process and print the prefix (encryption configs) first */
                    final VaultSpec spec = secure.vault.getSpec();
                    final String json = new ObjectMapper().writeValueAsString(spec);
                    final Reader reader = new StringReader(json);
                    final Configurations encryption = new JsonConfigurations(reader).prefix(PREFIX);
                    System.out.println("#");
                    System.out.println("# Encryption detils");
                    System.out.println("#");
                    encryption.list(System.err);
                } catch (IOException exception) {
                    System.err.println("Error processing details");
                    exception.printStackTrace(System.err);
                    System.exit(2);
                }

                System.out.println("#");
                System.out.println("# Configuration values");
                System.out.println("#");

                final SortedSet<String> normalize = new TreeSet<>(secure.plainKeys);
                secure.encryptedKeys.forEach((key) -> normalize.add(key + SUFFIX));
                normalize.forEach((key) -> System.out.printf("%s = %s\n", key, secure.configurations.get(key)));
                break;

            default:
                throw new UnsupportedOperationException("Unknown operation " + operation.get());

        }

        /* Wipe configurations/password */
        secure.close();
    }
}
