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

import org.usrz.libs.configurations.Configurations;

/**
 * A simple factory to create {@link KDF} instances out of specifications.
 *
 * @author <a href="mailto:pier@usrz.com">Pier Fumagalli</a>
 */
public interface KDFManager {

    /**
     * Return a {@link KDF} instance associated with the specified
     * {@link KDFSpec}.
     */
    public KDF getKDF(KDFSpec spec);

    /**
     * Return a {@link KDF} instance creating the {@link KDFSpec} required
     * for its creation from a {@link Configurations} instance.
     */
    default KDF getKDF(Configurations configurations) {
        return this.getKDF(new KDFSpecBuilder(configurations).build());
    }

}
