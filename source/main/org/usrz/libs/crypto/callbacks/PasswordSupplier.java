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
package org.usrz.libs.crypto.callbacks;

import java.io.IOException;
import java.util.function.Supplier;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.usrz.libs.utils.Check;

public class PasswordSupplier implements Supplier<char[]> {

    private final CallbackHandler handler;
    private final String prompt;

    public PasswordSupplier(CallbackHandler handler) {
        this(handler, null);
    }

    public PasswordSupplier(CallbackHandler handler, String prompt) {
        this.handler = Check.notNull(handler, "Null callback handler");
        this.prompt = prompt == null ? "Enter password" : prompt;
    }

    @Override
    public char[] get() {
        final PasswordCallback callback = new PasswordCallback(prompt, false);
        try {
            handler.handle(new Callback[] { callback });
            final char[] password = callback.getPassword();
            final char[] copy = new char[password.length];
            System.arraycopy(password, 0, copy, 0, password.length);
            callback.clearPassword();
            return copy;
        } catch (UnsupportedCallbackException | IOException exception) {
            throw new IllegalStateException("Exception handling password callback", exception);
        }
    }
}
