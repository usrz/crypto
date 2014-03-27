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

import static java.util.concurrent.TimeUnit.MINUTES;

import java.util.concurrent.TimeUnit;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * A {@link KDFManager} caching created {@link KDF} instances.
 */
public class CachingKDFManager implements KDFManager {

    private final LoadingCache<KDFSpec, KDF> cache;

    /**
     * Default constructor caching a maximum of 100 {@link KDF}s for up to
     * 10 minutes.
     */
    public CachingKDFManager() {
        this(100, 10, MINUTES);
    }

    /**
     * Create a {@link CachingKDFManager} containing up to <em>maximumSize</em>
     * {@link KDF} instances for the specified amount of time.
     */
    public CachingKDFManager(int maximumSize, long timeout, TimeUnit unit) {
        final KDFManager manager = new BasicKDFManager();
        cache = CacheBuilder.newBuilder()
                            .expireAfterAccess(timeout, unit)
                            .maximumSize(maximumSize)
                            .build(new CacheLoader<KDFSpec, KDF> () {
            @Override
            public KDF load(KDFSpec kdfSpec) {
                return manager.getKDF(kdfSpec);
            }
        });
    }

    @Override
    public KDF getKDF(KDFSpec kdfSpec) {
        return cache.getUnchecked(kdfSpec);
    }
}
