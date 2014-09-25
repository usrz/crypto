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
package org.usrz.libs.crypto.json;

import static org.usrz.libs.crypto.utils.CryptoUtils.safeEncode;
import static org.usrz.libs.utils.Check.notNull;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.usrz.libs.configurations.Password;
import org.usrz.libs.crypto.utils.ClosingDestroyable;
import org.usrz.libs.crypto.utils.CryptoUtils;
import org.usrz.libs.crypto.vault.Crypto;
import org.usrz.libs.crypto.vault.CryptoSpec;
import org.usrz.libs.logging.Log;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

public class EncryptedPasswords implements ClosingDestroyable {

    private boolean destroyed;
    private final CryptoSpec spec;
    private final ConcurrentMap<String, byte[]> data;

    @JsonCreator
    public EncryptedPasswords(@JsonProperty("spec") CryptoSpec spec,
                             @JsonProperty("data") Map<String, byte[]> data) {
        this.spec = notNull(spec, "Null spec");
        this.data = new ConcurrentHashMap<>(notNull(data, "Null data"));
    }

    @JsonIgnore
    public EncryptedPasswords(Crypto crypto) {
        spec = crypto.getSpec();
        data = new ConcurrentHashMap<>();
    }

    /* ====================================================================== */

    @JsonProperty("spec")
    public CryptoSpec getCryptoSpec() {
        return spec;
    }

    @JsonProperty("data")
    public Map<String, byte[]> getEncryptedData() {
        if (destroyed) throw new IllegalStateException("Destroyed");
        return Collections.unmodifiableMap(data);
    }

    /* ====================================================================== */

    @JsonIgnore
    public Password decrypt(Crypto crypto, String key) {
        if (destroyed) throw new IllegalStateException("Destroyed");

        /* Check the KDF spec we got */
        if (!crypto.getSpec().equals(getCryptoSpec()))
            throw new IllegalArgumentException("Crypto spec mismatch");

        /* Decrypt the password */
        try {
            final byte[] bytes = crypto.decrypt(data.get(notNull(key, "Null key")));
            if (bytes == null) return null;

            final char[] chars = CryptoUtils.safeDecode(bytes, true);
            return new Password(chars);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Exception decrypting", exception);
        }
    }

    public void encrypt(Crypto crypto, String key, Password password) {
        if (destroyed) throw new IllegalStateException("Destroyed");

        /* Check the KDF spec we got */
        if (!crypto.getSpec().equals(getCryptoSpec()))
            throw new IllegalArgumentException("Crypto spec mismatch");

        byte[] bytes = null;
        byte[] previous = null;
        try {
            if (password == null) {
                previous = data.remove(key);
            } else {
                bytes = safeEncode(password.get(), false);
                previous = data.put(notNull(key, "Null key"), crypto.encrypt(bytes));
            }
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Exception encrypting", exception);
        } finally {
            CryptoUtils.destroyArray(bytes);
            CryptoUtils.destroyArray(previous);
        }
    }

    public void remove(String key) {
        CryptoUtils.destroyArray(data.remove(key));
    }

    /* ====================================================================== */

    @Override
    public void close() {
        if (! destroyed) try {
            final Iterator<Entry<String, byte[]>> iterator = data.entrySet().iterator();
            while (iterator.hasNext()) try {
                final Entry<String, byte[]> entry = iterator.next();
                CryptoUtils.destroyArray(entry.getValue());
                iterator.remove();
            } catch (Exception exception) {
                new Log().warn(exception, "Error destroying password");
            }
        } finally {
            destroyed = true;
        }
    }

    @Override
    @JsonIgnore
    public final boolean isDestroyed() {
        return destroyed;
    }

}
