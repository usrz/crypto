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

import java.io.Console;
import java.io.EOFException;
import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class ConsoleCallbacks implements CallbackHandler {

    public static final ConsoleCallbacks INSTANCE = new ConsoleCallbacks();

    private ConsoleCallbacks() {
        /* Deny public construction */
    }

    private String getDefault(String string, String defaultString) {
        return string == null ? defaultString : string.length() == 0 ? defaultString : string ;
    }

    @Override
    public synchronized void handle(Callback[] callbacks)
    throws IOException, UnsupportedCallbackException {
        final Console console = System.console();
        if (console == null) throw new IOException("Console not available");

        for (Callback callback: callbacks) {
            if (callback instanceof PasswordCallback) {
                final PasswordCallback password = (PasswordCallback) callback;
                final String prompt = getDefault(password.getPrompt(), "Enter password");

                char[] answer = console.readPassword("\u001b[34m%s\u001b[0m: ", prompt);
                if (answer == null) throw new EOFException();
                password.setPassword(answer);

            } else if (callback instanceof NameCallback) {
                final NameCallback name = (NameCallback) callback;
                final String prompt = getDefault(name.getPrompt(), "Enter name");
                final String defaultName = name.getDefaultName();

                if (defaultName == null) while (true) {
                    final String answer = console.readLine("\u001b[34m%s\u001b[0m: ", prompt);
                    if (answer == null) throw new EOFException();
                    if (answer.length() == 0) continue;
                    name.setName(answer);
                    break;

                } else {
                    final String answer = console.readLine("\u001b[34m%s\u001b[0m [\u001b[36m%s\u001b[0m]: ", prompt, defaultName);
                    if (answer == null) throw new EOFException();
                    if (answer.length() == 0) name.setName(defaultName);
                    else name.setName(answer);

                }

            } else if (callback instanceof TextInputCallback) {
                final TextInputCallback input = (TextInputCallback) callback;
                final String prompt = getDefault(input.getPrompt(), "Enter value");
                final String defaultText = input.getDefaultText();

                if (defaultText == null) while (true) {
                    final String answer = console.readLine("\u001b[34m%s\u001b[0m: ", prompt);
                    if (answer == null) throw new EOFException();
                    if (answer.length() == 0) continue;
                    input.setText(answer);
                    break;

                } else {
                    final String answer = console.readLine("\u001b[34m%s\u001b[0m [\u001b[36m%s\u001b[0m]: ", prompt, defaultText);
                    if (answer == null) throw new EOFException();
                    if (answer.length() == 0) input.setText(defaultText);
                    else input.setText(answer);

                }

            } else if (callback instanceof TextOutputCallback) {
                final TextOutputCallback output = (TextOutputCallback) callback;
                final String message = output.getMessage();
                switch (output.getMessageType()) {
                    case TextOutputCallback.INFORMATION:
                        console.format("\u001b[32m%s\u001b[0m\n", message); break;
                    case TextOutputCallback.WARNING:
                        console.format("\u001b[33mWARNING: %s\u001b[0m\n", message); break;
                    case TextOutputCallback.ERROR:
                        console.format("\u001b[31mERROR: %s\u001b[0m\n", message); break;
                    default:
                        console.format("\u001b[35m??? [%d]: %s\u001b[0m\n", output.getMessageType(), message); break;
                }

            } else {
                throw new UnsupportedCallbackException(callback, "Callback type not supported");
            }
        }
    }

//    /* Quick test, hard to unit test console... */
//    public static void main(String[] args)
//    throws Exception {
//        final Callback[] callbacks = new Callback[] {
//                new TextOutputCallback(TextOutputCallback.INFORMATION, "This is a normal message"),
//                new TextOutputCallback(TextOutputCallback.WARNING,     "This is a warning"),
//                new TextOutputCallback(TextOutputCallback.ERROR,       "This is an error"),
//                new TextInputCallback("Enter text without default"),
//                new TextInputCallback("Enter a value", "some default value"),
//                new NameCallback("Enter name without default"),
//                new NameCallback("Enter a name", "some default name"),
//                new PasswordCallback("Enter a password", false),
//        };
//        INSTANCE.handle(callbacks);
//    }

}
