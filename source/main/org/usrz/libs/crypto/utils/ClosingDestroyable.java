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
package org.usrz.libs.crypto.utils;

import java.io.Closeable;

import javax.security.auth.Destroyable;

/**
 * An interface combining {@link Closeable} and {@link Destroyable}, in order
 * to have compiler warning when instances of this are not closed/destroyed.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public interface ClosingDestroyable extends Closeable, Destroyable {

    /**
     * Actual implementation of the {@link #destroy()} method.
     */
    @Override
    public void close();

    /**
     * Override the default {@link Destroyable#destroy()} method by simply
     * invoking {@link #close()}, and not throwing any exception.
     */
    @Override
    @Deprecated
    default void destroy() {
        close();
    }

    /**
     * Keep this abstract, it <b>must</b> be implemented.
     */
    @Override
    public boolean isDestroyed();

}
